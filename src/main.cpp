#include <sys/types.h>
#include "Shclient.hpp"
#include <nlohmann/json.hpp>
#include <termios.h>
#include <algorithm>

using namespace std;
using json = nlohmann::json;

constexpr int ENTER_KEY_CODE = 10;
constexpr int BACKSPACE_KEY_CODE = 127;
std::string input_buffer;
bool loop = true;

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
        cout << "\r" << string(input_buffer.length(), ' ') << "\r";

        // Выводим номер и информацию устройства приславшего собитие
        mess << "От сервера принят статус устройства " << item.c_str() << ":\t";
        for (u_char c_state : state)
        {
            mess << hex << (int)c_state << " ";
        }
        shs.logger.log(WARNING, mess.str());

        // Восстанавливаем ввод пользователя
        cout << "> " << input_buffer;
        cout.flush();
    }
    catch (const exception &e)
    {
        cerr << e.what() << '\n';
    }
}

void test_in(Shclient &shs, bool &main_loop)
{
    if (input_buffer == "quit" || input_buffer == "q")
    {
        main_loop = false;
        shs.close_connection();
    }
    else
    {
        printf("\nCommand\t|\tDescription\nq, quit\t|\tExit\nh, help\t|\tPrint this message\n");
    }
    input_buffer.clear();
}

char* getCmdOption(char ** begin, char ** end, const string & option)
{
    char ** itr = find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const string& option)
{
    return find(begin, end, option) != end;
}

int main(int argc, char *argv[])
{
    if(cmdOptionExists(argv, argv+argc, "-h"))
    {
        cout << "-f <Путь к конфигурационному файлу>" << endl;
    }
    char * filename = getCmdOption(argv, argv + argc, "-f");
    string configFilePath;
    if (!filename)
    {
        cout << "Путь к конфигурационному файлу не указан. Использован файл по умолчанию." << endl;
        configFilePath = string("/root/shc-mqtt.conf");
    } else configFilePath = string(filename);

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = p_exit;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    ifstream f(configFilePath);
    json data = json::parse(f);

    Shclient shs(data["ip20"], data["port20"], data["key20"], INFO);

    shs.init();
    shs.registerHandler(test_out);
    shs.requestAllDevicesState();
    shs.startLister();

    while (loop)
    {
        char ch = getChar();
        switch ((int)ch)
        {
        case ENTER_KEY_CODE:
            test_in(shs, loop);
            break;
        case BACKSPACE_KEY_CODE:
            if (input_buffer.length())
            {
                input_buffer.pop_back();
                std::cout << "\b\b\b   \b\b\b";
            }
            break;
        default:
            input_buffer += ch;
        }
    }

    cout << "End of " << argv[0] << endl;
    return 0;
}
