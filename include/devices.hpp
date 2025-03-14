#include <iostream>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <string>
#include <map>
#include <functional>
#include <pugixml.hpp>
#include "Shclient.hpp"

class dev_action_listener : public virtual mqtt::iaction_listener
{
    std::string name_;
    Shclient* shc;

    void on_failure(const mqtt::token& tok) override
    {
        stringstream mess;
        mess << name_ << " failure";
        if (tok.get_message_id() != 0)
            mess << " for token: [" << tok.get_message_id() << "]" << std::endl;
        shc->logger.log(INFO, mess.str());
    }

    void on_success(const mqtt::token& tok) override
    {
        stringstream mess;
        mess << name_ << " success";
        if (tok.get_message_id() != 0)
        mess << " for token: [" << tok.get_message_id() << "]";
        auto top = tok.get_topics();
        if (top && !top->empty())
            mess << "\ttoken topic: '" << (*top)[0];
        shc->logger.log(INFO, mess.str());
    }

public:
    dev_action_listener(const std::string& name, Shclient& shc) : name_(name), shc(&shc) {}
};

class Device {
    public:
        string addr;
        string type;
        string name;
        string command_topic;
        string state_topic;
        int qos = 1;
        int id, sid;
        pugi::xml_document xml_content;
        int state_len = 1;
        vector<uint8_t> state;
        Shclient* shc;
        dev_action_listener dev_subl;
    
        Device(const pugi::xml_node& node, const string addr, const string type, Shclient& shc) : addr(addr), type(type), shc(&shc), dev_subl("Device sub", shc){
            id = atoi(addr.substr(0, 3).c_str());
            sid = atoi(addr.substr(4, -1).c_str());
            stringstream topic;
            topic << "cuarm/" << id << "/" << sid;
            command_topic = topic.str() + "/command";
            state_topic = topic.str() + "/state";
            shc.mqttc->subscribe(command_topic, qos, nullptr, dev_subl);
            xml_content.append_child(pugi::node_declaration).append_attribute("version").set_value("1.0");
            xml_content.child("?xml").append_attribute("encoding").set_value("UTF-8");
            set_xml(node);
        }

        // Виртуальный деструктор
        virtual ~Device() = default;

        // Сохраняем XML-представление элемента
        void set_xml(const pugi::xml_node& node) {
            name = node.attribute("name").as_string();
            xml_content.remove_child("item");
            xml_content.append_copy(node);
        }

        virtual void print_state(){
            printf("%d\n", state[0]);
            cout << endl;
        }
    
        void set_state_from_srv(const vector<uint8_t>& new_state) {
            state = new_state;
            send_mqtt_msg();
        }

        virtual void set_state_to_srv(vector<uint8_t>& new_state) {
            shc->set_state(id, sid, new_state);
        }

        void send_mqtt_msg()
        {
            try
            {
                stringstream payload;
                for (auto it : state) payload << hex << (int)it << " ";
                mqtt::message_ptr pubmsg = mqtt::make_message(state_topic, payload.str());
                pubmsg->set_qos(qos);
                shc->mqttc->publish(pubmsg);
                shc->logger.log(INFO, "Send msg to MQTT. Topic: '"+state_topic+"' Payload: '"+payload.str()+"'");
            }
            catch (const exception &e)
            {
                cerr << e.what() << '\n';
            }
        }
    };
    
class Heating : public Device {
    public:

        string automation;
        unordered_map<string, int> automations;

        Heating(const pugi::xml_node& node, const string addr, const string type, Shclient& shc) : Device(node, addr, type, shc) {
            set_auto();
        }
    
        void set_auto()
        {
            for (auto it: xml_content.child("item").children()) {
                automations.insert_or_assign(it.attribute("name").as_string(), it.attribute("temperature-level").as_int(0));
            }
            automation = xml_content.child("item").attribute("automation").as_string("manual");
        }

        void send_xml_cmd() {
            pugi::xml_document xml_cmd;
            xml_cmd.append_child(pugi::node_declaration).append_attribute("version").set_value("1.0");
            xml_cmd.child("?xml").append_attribute("encoding").set_value("UTF-8");
            pugi::xml_node cmdNode = xml_cmd.append_child("smart-house-commands");
            cmdNode.append_copy(xml_content.child("item"));
            stringstream xml;
            xml_cmd.print(xml);
            shc->sendXmlToServer(xml.str());
            xml_cmd.print(std::cout);
        }

        void set_state_to_srv(vector<uint8_t>& new_state) {
            if (automation != "manual") {
                xml_content.child("item").remove_attribute("automation");
                automation = "manual";
                shc->logger.log(INFO, "Send xml to server by set_state_to_srv");
                send_xml_cmd();
                set_auto();
            }
            shc->set_state(id, sid, new_state);
        }

        void set_auto_to_srv(const string auto_t="", const int temp_t=0) {
            if (auto_t != ""){
                automation = auto_t;
                if (xml_content.child("item").attribute("automation").as_string("") == "") xml_content.child("item").append_attribute("automation");
                xml_content.child("item").attribute("automation").set_value(auto_t.c_str());
            }
            if (temp_t){
                pugi::xml_node item = xml_content.child("item");
                for (pugi::xml_node::iterator it = item.begin(); it != item.end(); ++it) {
                    pugi::xml_node node = *it;
                    if (strcmp(node.attribute("name").as_string(""), automation.c_str()) == 0)
                    {
                        node.attribute("temperature-level").set_value(temp_t);
                        break;
                    }
                    if (std::next(it) == item.end()) {
                        cout << "Last node" << endl;
                        pugi::xml_node auto_c = item.append_child("automation");
                        auto_c.append_attribute("name").set_value(auto_t);
                        auto_c.append_attribute("temperature-level").set_value(temp_t);
                    }
                }
            }
            shc->logger.log(INFO, "Send xml to server by set_auto_to_srv");
            send_xml_cmd();
            set_auto();
        }
};

class Dimmer : public Device {
    public:
        string automation;
        int state_len = 3;

        Dimmer(const pugi::xml_node& node, const string addr, const string type, Shclient& shc) : Device(node, addr, type, shc) {}

        void print_state(){
            printf("Power: %d Brs: %d\n", state[0], (int)round(static_cast<double>(state[1]) / 2.5));
            cout << endl;
        };

        void set_state_to_srv(vector<uint8_t>& new_state) {
            if (new_state.size() == 2) {
                new_state.push_back(0);
            }
            shc->set_state(id, sid, new_state);
        }
};

class Rgb : public Device {
    public:
        string automation;
        int state_len = 4;

        Rgb(const pugi::xml_node& node, const string addr, const string type, Shclient& shc) : Device(node, addr, type, shc) {}

        void print_state(){
            printf("Power: %d Brs: %d Sat: %d Hue: %d\n", state[0], (int)round(static_cast<double>(state[1]) / 2.5), (int)round(static_cast<double>(state[2]) / 2.5), (int)round(static_cast<double>(state[3]) / 2.5));
            cout << endl;
        }

        void set_state_to_srv(vector<uint8_t>& new_state) {
            if (new_state.size() == 2) {
                new_state.push_back(state[2]);
            }
            shc->set_state(id, sid, new_state);
        }
};
