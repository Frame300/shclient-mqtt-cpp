#include "Shclient.hpp"
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

bool loop = true;

void p_exit(int s)
{
    printf("Caught signal %d\n", s);
    loop = false;
}

void test_out(Shclient &shs, string item, string state)
{
    try
    {
        std::stringstream mess;
        mess <<  "От сервера принят статус устройства " << item.c_str() << ":\t";
        for (u_char c_state : state) {
            mess << hex << (int)c_state << " ";
        }
        shs.logger.log(WARNING, mess.str());
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

int main(int argc, char *argv[])
{
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = p_exit;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    ifstream f("shc-mqtt.conf");
    json data = json::parse(f);

    Shclient shs(data["ip20"],
                 data["port20"],
                 data["key20"],
                 INFO);

    shs.init();
    shs.registerHandler(test_out);
    shs.requestAllDevicesState();
    shs.startLister();

    std::string input;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, input);
        if (!loop || input == "quit" || input == "q") {
            break;
        }
        else
        {
            printf("Connamd\tDescription\nq, quit\tExit\nh, help\tPrint this message\n");
        }
    }


    shs.close_connection();
    cout << "End of " << argv[0] << endl;
    return 0;
}
