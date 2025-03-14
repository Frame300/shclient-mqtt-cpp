#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <algorithm>
#include <vector>

#include <termios.h>
#include <sys/types.h>
#include <nlohmann/json.hpp>

#include "mqtt/async_client.h"
#include "devices.hpp"
#include "Shclient.hpp"
#include "logger.h"

const std::string DFLT_SERVER_URI("192.168.1.125:1883");
const std::string CLIENT_ID("shc-mqtt-cpp");
const std::string TOPIC("cuarm/discovery/#");
const std::string SH_PORT = "22522";
const std::string SH_ADDR = "192.168.1.125";
const std::string SH_KEY = "1234567890123456";

Logger LOGGER = Logger("shc-mqtt.log");
const int ENTER_KEY_CODE = 10;
const int BACKSPACE_KEY_CODE = 127;
bool loop = true;

const int QOS = 1;
const int N_RETRY_ATTEMPTS = 5;
const auto TIMEOUT = std::chrono::seconds(1);

/////////////////////////////////////////////////////////////////////////////

// Callbacks for the success or failures of requested actions.
// This could be used to initiate further action, but here we just log the
// results to the console.

vector<string> customSplit(string str, char* separator) {
    vector < string > strings;
    int startIndex = 0, endIndex = 0;
    for (int i = 0; i <= str.size(); i++) {
        if (str[i] == *separator || i == str.size()) {
            endIndex = i;
            string temp;
            temp.append(str, startIndex, endIndex - startIndex);
            if (startIndex != endIndex) strings.push_back(temp);
            startIndex = endIndex + 1;
        }
    }
    return vector<string>(strings.begin(), strings.end());
}

void p_exit(int s)
{
    printf("Caught signal %d\n", s);
    loop = false;
}

char getChar()
{
    struct termios oldt, newt;
    char ch;
    tcgetattr(STDIN_FILENO, &oldt); // Получаем текущие настройки терминала
    newt = oldt;
    newt.c_lflag &= ~(ICANON); // Выключаем канонический режим для перехвата всех нажатий до нажатия ENTER
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    ch = getchar(); // Читаем один символ
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Восстанавливаем настройки
    return ch;
}

void test_out(Shclient &shs, string item, string state)
{
    try
    {
        stringstream mess;

        // Очищаем текущую строку ввода (Переводим "каретку" в начало, заполняем пробелами и снова переводим в начало)
        cout << "\r" << string(LOGGER.input_buffer.length(), ' ') << "\r";

        // Выводим номер и информацию устройства приславшего собитие
        // mess << "От сервера принят статус устройства " << item.c_str() << ":\t";
        // mess << "Type: " << shs.devfactory.get_device(item)->get()->type << ":\t";
        for (u_char c_state : state)
        {
            mess << hex << (int)c_state << " ";
        }
        // LOGGER.log(WARNING, mess.str());

        // Восстанавливаем ввод пользователя
        cout << "> " << LOGGER.input_buffer;
        cout.flush();
    }
    catch (const exception &e)
    {
        cerr << e.what() << '\n';
    }
}

void test_in(Shclient &shs, bool &main_loop)
{
    if (LOGGER.input_buffer == "quit" || LOGGER.input_buffer == "q")
    {
        main_loop = false;
        shs.close_connection();
    }
    else if (LOGGER.input_buffer.substr(0, 11) == "req all dev")
    {
        shs.requestAllDevicesState();
    }
    else if (LOGGER.input_buffer.substr(0, 2) == "up")
    {
        shs.update_cans();
    }
    else if (LOGGER.input_buffer.substr(0, 6) == "get id")
    {
        shs.get_id();
    }
    else if (LOGGER.input_buffer.substr(0, 7) == "get utc")
    {
        shs.get_utc();
    }
    else if (LOGGER.input_buffer.substr(0, 8) == "set item")
    {
        shs.set_item();
    }
    else if (LOGGER.input_buffer.substr(0, 9) == "set state")
    {
        string str = LOGGER.input_buffer.substr(10, -1);
        char sepSp[] = " ";
        char sepDp[] = ":";
        vector<string> Strings = customSplit(str, sepSp);
        vector<string> AddrStr = customSplit(Strings[0], sepDp);
        int ID = atoi(AddrStr[0].c_str());
        int SID = atoi(AddrStr[1].c_str());
        vector<u_char> state;
        for (vector<string>::iterator v_it = Strings.begin()+1; v_it != Strings.end(); ++v_it)
        {
             state.push_back(atoi((*v_it).c_str()));
        }
        // shs.set_state(ID, SID, state);
        auto dev_point = shs.devfactory->get_device(Strings[0]);
        if (dev_point) dev_point->get()->set_state_to_srv(state);
        else LOGGER.log(WARNING, "Устройство не найдено");
    }
    else
    {
        printf("Использование\n"
            "  > комманда [опции]\n\n"
            "Комманда <опции>:\n"
            "  set state <ID>:<SID>       установить сост. устройству\n"
            "  get utc                    запрос даты с сервера\n"
            "  get id                     запрос id сервера\n"
            "  up                         пинг устройств шины can\n"
            "  req all dev                запрос сост. всех устройств\n"
            "  h, help                    вывод этого сообщения\n"
            "  q, quit                    выход\n");
    }
    LOGGER.input_buffer.clear();
    cout << "> ";
}

char* getCmdOption(char ** begin, char ** end, const std::string & option)
{
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}

class action_listener : public virtual mqtt::iaction_listener
{
    std::string name_;

    void on_failure(const mqtt::token& tok) override
    {
        std::cout << name_ << " failure";
        if (tok.get_message_id() != 0)
            std::cout << " for token: [" << tok.get_message_id() << "]" << std::endl;
        std::cout << std::endl;
    }

    void on_success(const mqtt::token& tok) override
    {
        std::cout << name_ << " success";
        if (tok.get_message_id() != 0)
            std::cout << " for token: [" << tok.get_message_id() << "]" << std::endl;
        auto top = tok.get_topics();
        if (top && !top->empty())
            std::cout << "\ttoken topic: '" << (*top)[0] << "', ..." << std::endl;
        std::cout << std::endl;
    }

    public:
    action_listener(const std::string& name) : name_(name) {}
};

class callback : public virtual mqtt::callback, public virtual mqtt::iaction_listener {
    // Counter for the number of connection retries
    int nretry_;
    // The MQTT client
    mqtt::async_client& cli_;
    // Options to use if we need to reconnect
    mqtt::connect_options& connOpts_;
    // An action listener to display the result of actions.
    action_listener subListener_;
    Shclient& shs_;

    // This deomonstrates manually reconnecting to the broker by calling
    // connect() again. This is a possibility for an application that keeps
    // a copy of it's original connect_options, or if the app wants to
    // reconnect with different options.
    // Another way this can be done manually, if using the same options, is
    // to just call the async_client::reconnect() method.
    void reconnect()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        try {
            cli_.connect(connOpts_, nullptr, *this);
        }
        catch (const mqtt::exception& exc) {
            std::cerr << "Error: " << exc.what() << std::endl;
            exit(1);
        }
    }

    // Re-connection failure
    void on_failure(const mqtt::token& tok) override
    {
        LOGGER.log(ERROR, "Connection attempt failed");
        if (++nretry_ > N_RETRY_ATTEMPTS)
            exit(1);
        reconnect();
    }

    // (Re)connection success
    // Either this or connected() can be used for callbacks.
    void on_success(const mqtt::token& tok) override {}

    // (Re)connection success
    void connected(const std::string& cause) override
    {
        std::cout << "\nConnection success" << std::endl;
        std::cout << "\nSubscribing to topic '" << TOPIC << "'\n"
                << "\tfor client " << CLIENT_ID << " using QoS" << QOS << "\n"
                << "\nPress Q<Enter> to quit\n"
                << std::endl;

        cli_.subscribe(TOPIC, QOS, nullptr, subListener_);
    }

    // Callback for when the connection is lost.
    // This will initiate the attempt to manually reconnect.
    void connection_lost(const std::string& cause) override
    {
        std::cout << "\nConnection lost" << std::endl;
        if (!cause.empty())
            std::cout << "\tcause: " << cause << std::endl;

        std::cout << "Reconnecting..." << std::endl;
        nretry_ = 0;
        reconnect();
    }

    // Callback for when a message arrives.
    void message_arrived(mqtt::const_message_ptr msg) override
    {
        stringstream mess;
        mess << "Message arrived. Topic: '" << msg->get_topic()
            << "'Payload: '" << msg->to_string();
        LOGGER.log(INFO, mess.str());
        
        // const mqtt::properties& props = msg->get_properties();
        // if (size_t n = props.size(); n != 0) {
        //     std::cout << "\tproperties (" << n << "):\n\t  [";
        //     for (size_t i = 0; i < n - 1; ++i) std::cout << props[i] << ", ";
        //     std::cout << props[n - 1] << "]" << std::endl;
        // }
        try
        {
            char sepSl[] = "/";
            char sepSp[] = " ";
            vector<string> Strings = customSplit(msg->get_topic(), sepSl);
            if (Strings.size() == 4 && Strings[0] == "cuarm" && Strings.back() == "command")
            {
                std::string idSid = Strings[1]+":"+Strings[2];
                auto device_ptr = shs_.devfactory->get_device(idSid);
                if (device_ptr) {
                    auto device = device_ptr->get();
                    std::string mqtt_msg = msg->to_string();
                    if (mqtt_msg[0] > 57 && device->type == "valve-heating") {
                        Strings = customSplit(mqtt_msg, sepSp);
                        dynamic_cast<Shclient::Heating*>(device)->
                                set_auto_to_srv(Strings[0], Strings.size() > 1 ? atoi((Strings[1]).c_str()) : 0);
                    } else {
                        vector<u_char> state = {};
                        Strings = customSplit(mqtt_msg, sepSp);
                        for (vector<string>::iterator v_it = Strings.begin(); v_it != Strings.end(); ++v_it)
                        {
                            state.push_back(atoi((*v_it).c_str()));
                        }
                        device->set_state_to_srv(state);
                    }
                }
            }
            else LOGGER.log(WARNING, "Устройство не найдено");
        }
        catch (const exception &e)
        {
            LOGGER.log(ERROR, e.what());
        }
    
    }

    void delivery_complete(mqtt::delivery_token_ptr token) override {}

public:
    callback(mqtt::async_client& cli, mqtt::connect_options& connOpts, Shclient& shs)
        : nretry_(0), cli_(cli), shs_(shs), connOpts_(connOpts), subListener_("Subscription")
    {
    }

};


using namespace std;
using json = nlohmann::json;

int main(int argc, char* argv[])
{
    if(cmdOptionExists(argv, argv+argc, "-h"))
    {
        cout << "-f <path_to_config_file>" << endl;
    }
    char * configFilePath = getCmdOption(argv, argv + argc, "-f");
    if (!configFilePath)
    {
        cout << "No config specified" << endl;
        return 0;
    }

    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = p_exit;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    LOGGER.setLevel(INFO);

    ifstream f(configFilePath);
    json data = json::parse(f);
    
    auto serverURI = "mqtt://"+(data.contains("mqtt_host") ? string(data["mqtt_host"]) : DFLT_SERVER_URI);
    cout << "MQTT server: '" << serverURI << "'";
    auto sh_addr = data.contains("ip20") ? string(data["ip20"]) : SH_ADDR;
    auto sh_port = data.contains("port20") ? string(data["port20"]) : SH_PORT;
    auto sh_key = data.contains("key20") ? string(data["key20"]) : SH_KEY;

    Shclient shs(sh_addr, sh_port, sh_key, LOGGER);
    mqtt::async_client cli(serverURI, CLIENT_ID);
    shs.set_mqttc(cli);

    auto connOpts = mqtt::connect_options_builder::v5()
        .clean_start(true)
        .finalize();
    connOpts.set_user_name("mimi");
    connOpts.set_password("smart");

    // Install the callback(s) before connecting.
    callback cb(cli, connOpts, shs);
    cli.set_callback(cb);

    // Start the connection.
    // When completed, the callback will subscribe to topic.

    try {
        cout << "Connecting to the MQTT server '" << serverURI << "'..." << endl;
        cli.connect(connOpts, nullptr, cb);
    }
    catch (const mqtt::exception& exc) {
        cerr << "\nERROR: Unable to connect to MQTT server: '" << serverURI << "'" << exc
                << endl;
        return 1;
    }

    cout << "SmartHouse server '" << sh_addr << ":" << sh_port << endl;
    shs.init();
    shs.startLister();

    // Just block till user tells us to quit.
    while (loop)
    {
        char ch = getChar();
        switch ((int)ch)
        {
        case ENTER_KEY_CODE:
            test_in(shs, loop);
            break;
        case BACKSPACE_KEY_CODE:
            if (LOGGER.input_buffer.length())
            {
                LOGGER.input_buffer.pop_back();
                cout << "\b\b\b   \b\b\b";
            }
            break;
        default:
            LOGGER.input_buffer += ch;
        }
    }

    // Disconnect

    try {
        cout << endl;
        cout << "Disconnecting from the MQTT server...";
        cli.disconnect()->wait();
        cout << "OK" << endl;
        cout << "Disconnecting from the SH server...";
        shs.close_connection();
        cout << "OK" << endl;
    }
    catch (const mqtt::exception& exc) {
        cerr << exc << endl;
        return 1;
    }

    return 0;
}