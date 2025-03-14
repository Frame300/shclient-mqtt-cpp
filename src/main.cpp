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

const std::string DFLT_SERVER_URI("mqtt://89.17.55.74:36583");
const std::string CLIENT_ID("shc-mqtt-cpp");
const std::string TOPIC("cuarm/discovery/#");

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

// void srv_msg(Shclient& shs, mqtt::async_client& mqttc, string item, string state)
// {
//     try
//     {
//         std::unique_ptr<Shclient::Device>* dev = shs.devfactory->get_device(item);
//         if (dev) {
//             Shclient::Device* device = dev->get();

//             stringstream topic;
//             topic << "mimismart/" << device->id
//             << "/" << device->sid << "/state";

//             stringstream payload;
//             for (u_char c_state : state)
//             {
//                 payload << hex << (int)c_state << " ";
//             }

//             mqtt::message_ptr pubmsg = mqtt::make_message(topic.str(), payload.str());
//             pubmsg->set_qos(QOS);
//             mqttc.publish(pubmsg)->wait_for(TIMEOUT);
//             shs.logger.log(INFO, "Send msg to MQTT. Topic: '"+topic.str()+"' Payload: '"+payload.str()+"'");
//         } else {
//             shs.logger.log(WARNING, "Device '"+item+"'  not found in logic.");
//         }
//     }
//     catch (const exception &e)
//     {
//         cerr << e.what() << '\n';
//     }
// }

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

/////////////////////////////////////////////////////////////////////////////

/**
* Local callback & listener class for use with the client connection.
* This is primarily intended to receive messages, but it will also monitor
* the connection to the broker. If the connection is lost, it will attempt
* to restore the connection and re-subscribe to the topic.
*/
class callback : public virtual mqtt::callback, public virtual mqtt::iaction_listener

{
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
        std::cout << "Connection attempt failed" << std::endl;
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
        shs_.logger.log(INFO, mess.str());
        
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
                        dynamic_cast<Shclient::Heating*>(device)->set_auto_to_srv(Strings[0], atoi((Strings[1]).c_str()));
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
            else shs_.logger.log(WARNING, "Устройство не найдено");
        }
        catch (const exception &e)
        {
            shs_.logger.log(ERROR, e.what());
        }
    
    }

    void delivery_complete(mqtt::delivery_token_ptr token) override {}

public:
    callback(mqtt::async_client& cli, mqtt::connect_options& connOpts, Shclient& shs)
        : nretry_(0), cli_(cli), shs_(shs), connOpts_(connOpts), subListener_("Subscription")
    {
    }

};


int main(int argc, char* argv[])
{
    // A subscriber often wants the server to remember its messages when its
    // disconnected. In that case, it needs a unique ClientID and a
    // non-clean session.

    auto serverURI = (argc > 1) ? std::string{argv[1]} : DFLT_SERVER_URI;
    string sh_port = "36525";
    string sh_addr = "89.17.55.74";
    string sh_key = "1234567890123456";

    Shclient shs(sh_addr, sh_port, sh_key, INFO);
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
        std::cout << "Connecting to the MQTT server '" << serverURI << "'..." << std::flush;
        cli.connect(connOpts, nullptr, cb);
    }
    catch (const mqtt::exception& exc) {
        std::cerr << "\nERROR: Unable to connect to MQTT server: '" << serverURI << "'" << exc
                << std::endl;
        return 1;
    }

    std::cout << "shs.init() '" << sh_addr << ":" << sh_port << std::endl;
    shs.init();
    // shs.registerHandler(srv_msg);
    shs.startLister();

    // Just block till user tells us to quit.
    while (std::tolower(std::cin.get()) != 'q');

    // Disconnect

    try {
        std::cout << "\nDisconnecting from the MQTT server..." << std::flush;
        cli.disconnect()->wait();
        std::cout << "OK" << std::endl;
        shs.close_connection();
    }
    catch (const mqtt::exception& exc) {
        std::cerr << exc << std::endl;
        return 1;
    }

    return 0;
}