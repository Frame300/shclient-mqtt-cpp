#include <functional>
#include <iostream>
#include <string>
#include <cstring>
#include <cmath>
#include <vector>
#include <thread>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "logger.h"
#include <map>
#include <rapidxml.hpp>
#include <rapidxml_utils.hpp>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/select.h>

// Класс для взаимодействия с сервером МимиСмарт (2.0)
class Shclient
{
private:
    static const ssize_t AUTHORIZATION_DATA_SIZE = 16;   // Размер ключа AES128 всегда 16 байт
    static const uint32_t PD_REQUEST_ALL_DEVICES = 14;   // Request all devices. If we use with id module - this module returned first
    static const uint32_t PD_SET_STATUS_FROM_SERVER = 7; // State of single item from server
    static const uint32_t PD_SET_STATUS_TO_SERVER = 5;   // Set state to server
    static const uint32_t PD_START_PACKET = 1;
    static const uint32_t PD_SYNCHRO_TIME = 30;
    static const uint32_t PD_PING_MODULE = 15;
    static const uint32_t initClientDefValue = 0x7ef;
    bool allowRetraslateUDP = true;
    bool saveXmlLogic = true;
    int connectionResource, port, initClientID, n;
    std::string xmlFilePath = "logic.xml";
    std::string shl_end = "</smart-house>";
    std::string host, key;
    std::string logicXml;
    std::vector<u_char> buffer;
    std::map<std::string, std::map<std::string, std::string>> Items;
    std::vector<std::function<void(Shclient&, std::string, std::string)>> handlers;
    std::thread listener_thread;
    bool listener_running;


    void sendDataToHandlers(std::string item, std::string state)
    {
        for (auto &func : handlers)
        {
            func(*this, item, state);
        }
    }

    void _parceItems(rapidxml::xml_node<char> &node)
    {
        for (auto &child : node.children())
        {
            if (child.name() == "item")
            {
                map<string, string> item_attrs;
                string addr;
                for (auto &attr : child.attributes())
                {
                    if (attr.name() == "addr")
                    {
                        addr = attr.value();
                        continue;
                    }
                    item_attrs.insert_or_assign(string(attr.name()), string(attr.value()));
                }
                if (!item_attrs.contains("State"))
                {
                    item_attrs.insert_or_assign(string("State"), string("???"));
                }
                Items.insert_or_assign(string(addr), map<string, string>(item_attrs));
            }
            if (child.name() == "area")
            {
                _parceItems(child);
            }
        }
    }

    void parceItems(string xmlData)
    {
        rapidxml::xml_document<> doc;
        doc.parse<0>(xmlData);
        for (auto &child : doc.first_node()->children())
        {
            if (child.name() == "item")
            {
                map<string, string> item_attrs;
                string addr;
                for (auto &attr : child.attributes())
                {
                    if (attr.name() == "addr")
                    {
                        addr = attr.value();
                        continue;
                    }
                    item_attrs.insert_or_assign(string(attr.name()), string(attr.value()));
                }
                if (!item_attrs.contains("State"))
                {
                    item_attrs.insert_or_assign(string("State"), string("???"));
                }
                Items.insert_or_assign(string(addr), map<string, string>(item_attrs));
            }
            else if (child.name() == "area")
            {
                _parceItems(child);
            }
        }
    }

    void handleErrors()
    {
        fprintf(stderr, "An error occurred\n");
        exit(1);
    }

    void aes_ecb_encrypt(const unsigned char *plaintext, int plaintext_len,
                         const unsigned char *key, unsigned char *ciphertext)
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            handleErrors();

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)
            handleErrors();

        EVP_CIPHER_CTX_set_padding(ctx, 0); // ECB обычно используется без паддинга

        int len, ciphertext_len;
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
            handleErrors();
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
            handleErrors();
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
    }

    bool connect_to_srv()
    {
        connectionResource = socket(AF_INET, SOCK_STREAM, 0);
        if (connectionResource < 0)
        {
            logger.log(ERROR, "Ошибка создания сокета");
            return false;
        }
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0)
        {
            logger.log(ERROR, "Неверный IP-адрес");
            return false;
        }
        if (connect(connectionResource, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            logger.log(ERROR, "Ошибка подключения");
            return false;
        }
        char c_port[6];
        snprintf(c_port, sizeof(c_port), "%d", port);
        std::string mess = "Подключено к " + host + ":" + c_port;
        logger.log(INFO, mess);
        return true;
    }

    bool SetSocketBlocking(int fd, bool blocking)
    {
        if (fd < 0)
            return false;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1)
            return false;
        flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
        return (fcntl(fd, F_SETFL, flags) == 0);
    }

    void reconnect()
    {
        close_connection();
        sleep(1);
        connect_to_srv();
    }

    bool isConnected()
    {
        // Implementation to check connection
        int error_code;
        socklen_t error_code_size = sizeof(error_code);
        getsockopt(connectionResource, SOL_SOCKET, SO_ERROR, &error_code, &error_code_size);
        return true; //
    }

    bool authorization()
    {
        std::string data = fread(AUTHORIZATION_DATA_SIZE);
        unsigned char ciphertext[AUTHORIZATION_DATA_SIZE];
        aes_ecb_encrypt((u_char *)data.data(), AUTHORIZATION_DATA_SIZE, (u_char *)key.data(), ciphertext);
        if (send(connectionResource, ciphertext, AUTHORIZATION_DATA_SIZE, MSG_WAITALL) > 0)
        {
            logger.log(INFO, "Данные авторизации отправлены на сервер");
            return true;
        }
        else
        {
            logger.log(ERROR, "Ошибка отправки данных авторизации на сервер");
            return false;
        }
    }

    std::string fread(size_t expected_size)
    {
        std::vector<char> buffer;
        buffer.reserve(expected_size); // Резервируем место для n байт

        char temp_buffer; // Временный буфер
        int total_received = 0;

        while (total_received < expected_size)
        {
            int bytes_received = recv(connectionResource, &temp_buffer, 1, 0);
            if (bytes_received < 0)
            {
                std::cerr << "Ошибка приема данных\n";
                return "";
            }
            if (bytes_received == 0)
            {
                break; // Соединение закрыто сервером
            }

            buffer.insert(buffer.end(), 1, temp_buffer);
            total_received += bytes_received;
        }

        return std::string(buffer.begin(), buffer.end());
    }

    void sendToServer(std::string data)
    {
        size_t msg_len = data.size();
        n = send(connectionResource, &msg_len, 4, MSG_WAITALL) +
            send(connectionResource, data.data(), msg_len, MSG_WAITALL);
        if (n < 0)
            throw std::runtime_error("Writing to socket error in send xml data");
    }

    bool read_xml_logic()
    {
        std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<smart-house-commands>\n";
        if (allowRetraslateUDP)
            xml += "<get-shc retranslate-udp=\"yes\" />\n";
        else
            xml += "<get-shc mac-id=9c:3e:53:77:80:53/>\n";
        xml += "</smart-house-commands>\n";

        sendToServer(xml);

        if (isConnected())
        {
            int j = 0;
            while (logicXml.empty() && j < 3)
            {
                std::string data = fread(10);
                int length;
                u_int8_t shHead[6];
                std::memcpy(&length, data.data(), sizeof(length));
                std::memcpy(shHead, data.data() + 4, sizeof(shHead));

                if (!std::memcmp("shcxml", shHead, 6))
                {
                    std::string line = fread(4);
                    uint32_t crc;
                    std::memcpy(&crc, line.data(), sizeof(crc));

                    line = fread(1);
                    uint8_t addata;
                    std::memcpy(&addata, line.data(), sizeof(addata));
                    initClientID = initClientDefValue - line[0];

                    int receivedFileSize = length - 11;
                    logicXml = fread(receivedFileSize);

                    int real_size = logicXml.size() - (logicXml.size() - logicXml.find(shl_end));
                    logicXml.resize(real_size + shl_end.size());
                    parceItems(logicXml);

                    size_t begin, end;
                    ifstream ofs(xmlFilePath, ios::binary);
                    begin = ofs.tellg();
                    ofs.seekg(0, ios::end);
                    end = ofs.tellg();
                    ofs.close();

                    if (!logicXml.empty() && saveXmlLogic &&
                        (access(xmlFilePath.c_str(), F_OK) == -1 ||
                         (access(xmlFilePath.c_str(), F_OK) == 0 && (end - begin) != receivedFileSize)))
                    {
                        std::ofstream ofs(xmlFilePath);
                        if (ofs.is_open())
                        {
                            ofs << logicXml;
                            ofs.close();
                        }
                    }

                    logger.log(INFO, "Принят файл логики XML, Размер: " + to_string(receivedFileSize) +
                                         ", CRC32: " + to_string(crc) + ", присвоенный ID Клиента: " + to_string(initClientID));
                }
                else if (!std::memcmp("messag", shHead, 6))
                {
                    std::string message = fread(length - 6);
                    std::cout << "Server recieved 'messag': " << message << std::endl;
                }
                else
                {
                    std::string message = fread(length - 6);
                    std::cout << "Server recieved other data: " << message << std::endl;
                }
                j++;
                usleep(100000);
            }
        }
        else
        {
            return false;
        }
        return true;
    }

    struct UnpackDataExtended
    {
        u_int16_t sender_id;
        u_int16_t dest_id;
        u_int8_t pd;
        u_int8_t transid;
        u_int8_t sender_sub_id;
        u_int8_t dest_sub_id;
        u_int16_t length;
        UnpackDataExtended(u_int8_t *buff) : sender_id(buff[1] << 8 | buff[0]), dest_id(buff[3] << 8 | buff[2]),
                                             pd(buff[4]), transid(buff[5]), sender_sub_id(buff[6]), dest_sub_id(buff[7]), length(buff[9] << 8 | buff[8]) {}
    };

    struct CANData
    {
        u_short ucanid;
        u_short length;
        CANData(u_char *buff) : ucanid(buff[0]), length(buff[1]) {}
    };

public:
    Logger logger = Logger("shclient.log");

    Shclient(const std::string &host, const std::string &port, const std::string &key, LogLevel logLevel = DEBUG)
    {
        logger.setLevel(logLevel);
        this->host = host;
        this->port = atoi(port.c_str());
        this->key = key;
    };

    ~Shclient()
    {
        listener_running = false;
        close_connection();
    }

    // Инициализация
    // подключение к серверу, авторизация по ключу, получение логики
    int init()
    {
        if (connect_to_srv() && authorization() && read_xml_logic())
            return true;
        else
            return false;
    }

    // Закрывае соединение с сервером
    // Убивает поток приема событий, если он запущен
    void close_connection()
    {
        listener_running = false;
        if (listener_thread.joinable()) {
            listener_thread.join();
        }
        shutdown(connectionResource, 2);
        close(connectionResource);
    }

    // Запрос состояния всех устройств
    void requestAllDevicesState()
    {
        std::string data = {0, 0, PD_REQUEST_ALL_DEVICES, 0, 0, 0, 0};
        sendToServer(data);
    }

    void readDeviceStateEvent()
    {
        time_t check_loop = time(0);
        SetSocketBlocking(connectionResource, false);
        fd_set read_fd;
        FD_ZERO(&read_fd);

        while (listener_running)
        {
        if (time(0) - check_loop > 60)
        {
            check_loop = time(0);
            requestAllDevicesState();
        }

        if (!isConnected())
        {
            reconnect();
            return;
        }

        FD_SET(connectionResource, &read_fd);
        struct timeval timeout{.tv_sec = 1, .tv_usec = 0};
        int act = select(connectionResource + 1, &read_fd, nullptr, nullptr, &timeout);
        if (act < 1 && !FD_ISSET(connectionResource, &read_fd)) continue;

        std::string data = fread(10);
        u_int32_t length;
        u_int8_t shHead[6];
        std::memcpy(&length, data.data(), sizeof(length));
        std::memcpy(shHead, data.data() + 4, sizeof(shHead));

        if (!std::memcmp("ping", shHead, 4) || !std::memcmp("", shHead, 1))
        {
            std::cout << "Server ping" << std::endl;
        }
        else if (!std::memcmp("shcxml", shHead, 6))
        {
            std::string line = fread(4);
            uint32_t crc;
            std::memcpy(&crc, line.data(), sizeof(crc));

            line = fread(1);
            uint8_t addata;
            std::memcpy(&addata, line.data(), sizeof(addata));
            initClientID = initClientDefValue - addata;

            size_t receivedFileSize = length - 11;
            logicXml = fread(receivedFileSize);

            int real_size = logicXml.size() - (logicXml.size() - logicXml.find(shl_end));
            logicXml.resize(real_size + shl_end.size());
            parceItems(logicXml);
            if (!logicXml.empty() && saveXmlLogic)
            {
                std::ofstream ofs(xmlFilePath);
                if (ofs.is_open())
                {
                    ofs << logicXml;
                    ofs.close();
                }
            }

            logger.log(INFO, "Server recieved logicXml, FileSize: " + to_string(receivedFileSize) +
                                 ", CRC32: " + to_string(crc) + ", initClientID: " + to_string(initClientID));
        }
        else if (!std::memcmp("messag", shHead, 6))
        {
            std::string message = fread(length - 6);
            std::cout << "Server recieved 'messag': " << message << std::endl;
        }
        else
        {
            std::string IdSid;
            UnpackDataExtended unpackDataExt((uint8_t *)data.data());
            logger.log(DEBUG, "Device event data recieved. sender_id: " + std::to_string(unpackDataExt.sender_id) +
                                  ", dest_id: " + std::to_string(unpackDataExt.dest_id) +
                                  ", pd: " + std::to_string(unpackDataExt.pd) +
                                  ", transid: " + std::to_string(unpackDataExt.transid) +
                                  ", dest_sub_id: " + std::to_string(unpackDataExt.sender_sub_id) +
                                  ", sender_sub_id: " + std::to_string(unpackDataExt.dest_sub_id) +
                                  ", length: " + std::to_string(unpackDataExt.length));

            if (unpackDataExt.pd == PD_SET_STATUS_FROM_SERVER)
            {
                std::string line = fread(unpackDataExt.length);
                IdSid = std::to_string(unpackDataExt.sender_id) + ":" + std::to_string(unpackDataExt.sender_sub_id);
                if (std::memcmp(Items[IdSid]["State"].data(), line.data(), unpackDataExt.length))
                {
                    Items[IdSid]["State"] = line;
                    if (unpackDataExt.length == 1)
                    {
                        logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " " + Items[IdSid]["name"] + " State: " + std::to_string(line[0]));
                    }
                    else if (unpackDataExt.length == 2)
                    {
                        if (Items[IdSid]["type"] == "dimer-lamp")
                        {
                            logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " Power: " + (std::to_string(line[0])) + " Brightness: " + (std::to_string((int)round(static_cast<double>(line[1]) / 2.5))));
                        }
                        else
                        {
                            double value = line[1] << 8 | line[0];
                            double processedValue = 0.0;

                            if (value > 32768)
                            {
                                processedValue = round(((65536 - value) / -256.0) * 100) / 100.0;
                            }
                            else
                            {
                                processedValue = round((static_cast<double>(value) / 256.0) * 100) / 100.0;
                            }
                            logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " Value: " + (std::to_string(processedValue)));
                        }
                    }
                    else if (unpackDataExt.length > 2)
                    {
                        if (Items[IdSid]["type"] == "valve-heating")
                        {
                            logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " State: " + std::string(std::to_string((int)line[0])) + " Mode: " + (Items[IdSid].contains("automation") ? Items[IdSid]["automation"] : "Manual"));
                        }
                        else
                        {
                            char s_data[unpackDataExt.length];
                            for (int i = 0; i < unpackDataExt.length; ++i)
                            {
                                s_data[i] = line[i];
                            }
                            logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " Value: " + std::string(s_data));
                        }
                    }
                    sendDataToHandlers(IdSid, line);
                }
            }
            else if (unpackDataExt.pd == PD_PING_MODULE)
            {
                u_long dataLength = unpackDataExt.length;
                while (dataLength > 0)
                {
                    std::string line = fread(2);
                    dataLength -= 2;
                    CANData ucanData((u_char *)line.data());
                    std::string tmpdata = fread(ucanData.length);
                    dataLength -= ucanData.length;
                    IdSid = std::to_string(unpackDataExt.sender_id) + ":" + std::to_string(ucanData.ucanid);
                    if (std::memcmp(Items[IdSid]["State"].data(), tmpdata.data(), ucanData.length))
                    {
                        Items[IdSid]["State"] = tmpdata;
                        if (ucanData.length == 1)
                        {
                            logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " State: " + std::to_string(tmpdata[0]));
                        }
                        else if (ucanData.length == 2)
                        {
                            if (Items[IdSid]["type"] == "dimer-lamp")
                            {
                                logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " Power: " + (std::to_string(tmpdata[0])) + " Brightness: " + (std::to_string((int)round(static_cast<double>(tmpdata[1]) / 2.5))));
                            }
                            else
                            {
                                double value = tmpdata[1] << 8 | tmpdata[0];
                                double processedValue = 0.0;
                                if (value > 32768)
                                {
                                    processedValue = round(((65536 - value) / -256.0) * 100) / 100.0;
                                }
                                else
                                {
                                    processedValue = round((static_cast<double>(value) / 256.0) * 100) / 100.0;
                                }

                                logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " Value: " + (std::to_string(processedValue)));
                            }
                        }
                        else if (ucanData.length > 2)
                        {
                            if (Items[IdSid]["type"] == "valve-heating")
                            {
                                logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " State: " + std::string(std::to_string((int)tmpdata[0])) + " Mode: " + (Items[IdSid].contains("automation") ? Items[IdSid]["automation"] : "Manual"));
                            }
                            else
                            {
                                char s_data[ucanData.length];
                                for (int i = 0; i < ucanData.length; ++i)
                                {
                                    s_data[i] = tmpdata[i];
                                }
                                logger.log(DEBUG, IdSid + " " + Items[IdSid]["type"] + " Value: " + std::string(s_data));
                            }
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                    sendDataToHandlers(IdSid, tmpdata);
                }
            }
            else
            {
                std::string line = fread(unpackDataExt.length);
                std::cout << "Other data in Event listener: ";
                for (int i = 0; i < unpackDataExt.length; ++i)
                {
                    printf("0x%x ", line[i]);
                }
                std::cout << std::endl;
            }
        }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    }

    // Старт прослушивания событий от сервера
    void startLister() {
        listener_running = true;
        listener_thread = std::thread(&Shclient::readDeviceStateEvent, this);
    }

    // Метод для вызова пользовательских функций
    // На вход функция должа принимать (&Shclient, string, string):
    //     ссылка на объект: &Shclient
    //     адрес устройства: "ID:SID"
    //     полученный статус: <8и битный массив>
    void registerHandler(auto &func)
    {
        handlers.emplace_back(std::bind(func, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    }
};
