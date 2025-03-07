#include <sys/types.h>
#include "Shclient.hpp"
#include <nlohmann/json.hpp>
#include <termios.h>
#include <algorithm>
#include <vector>

using namespace std;
using json = nlohmann::json;

constexpr int ENTER_KEY_CODE = 10;
constexpr int BACKSPACE_KEY_CODE = 127;
std::string input_buffer;
bool loop = true;

vector<string> customSplit(string str, char separator) {
    vector < string > strings;
    int startIndex = 0, endIndex = 0;
    for (int i = 0; i <= str.size(); i++) {
        if (str[i] == separator || i == str.size()) {
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
    else if (input_buffer.substr(0, 11) == "req all dev")
    {
        shs.requestAllDevicesState();
    }
    else if (input_buffer.substr(0, 6) == "get id")
    {
        shs.get_id();
    }
    else if (input_buffer.substr(0, 7) == "get utc")
    {
        shs.get_utc();
    }
    else if (input_buffer.substr(0, 8) == "set item")
    {
        shs.set_item();
    }
    else if (input_buffer.substr(0, 9) == "set state")
    {
        string str = input_buffer.substr(10, -1);
        char sep[] = " ";
        vector<string> Strings = customSplit(str, sep[0]);
        int ID = atoi(Strings[0].substr(0, 3).c_str());
        int SID = atoi(Strings[0].substr(4, -1).c_str());
        vector<u_char> state;
        for (vector<string>::iterator v_it = Strings.begin()+1; v_it != Strings.end(); ++v_it)
        {
             state.push_back(atoi((*v_it).c_str()));
        }
        shs.set_state(ID, SID, state);
    }
    else
    {
        printf("Использование\n"
            "  > комманда [опции]\n\n"
            "Комманда <опции>:\n"
            "  set state <ID>:<SID>       установить сост. устройству\n"
            "  get utc                    запрос даты с сервера\n"
            "  get id                     запрос id сервера\n"
            "  req all dev                запрос сост. всех устройств\n"
            "  h, help                    вывод этого сообщения\n"
            "  q, quit                    выход\n");
    }
    input_buffer.clear();
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

int main(int argc, char *argv[])
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

    ifstream f(configFilePath);
    json data = json::parse(f);

    Shclient shs(data["ip20"], data["port20"], data["key20"], INFO);

    shs.init();
    shs.registerHandler(test_out);
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
