#include <iostream>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <string>
#include <map>
#include <functional>
#include <pugixml.hpp>
#include "Shclient.hpp"


class Device {
    public:
        string addr;
        string type;
        string name;
        int id, sid;
        pugi::xml_document xml_content;
        const static int state_len = 1;
        vector<uint8_t> state;
        Shclient* shc;
    
        Device(const pugi::xml_node& node, const string addr, const string type, Shclient& shc) : addr(addr), type(type), shc(&shc){
            id = atoi(addr.substr(0, 3).c_str());
            sid = atoi(addr.substr(4, -1).c_str());
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
            cout << endl << "State " << type << "(" << addr << ") from srv: ";
            print_state();
        }

        virtual void set_state_to_srv(const vector<uint8_t>& new_state) {
            state = new_state;
            cout << endl << "New state " << type << "(" << addr << ") to srv: ";
            print_state();
            shc->set_state(id, sid, state);
        }
    
        void set_link(Shclient& shc) {
            this->shc = &shc;
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

        void set_state_to_srv(const string auto_t="", const int temp_t=0,
            const function<void(const int, const string&, const vector<uint8_t>&)>& handler = 0) {
            if (auto_t!=""){
                automation = auto_t;
                xml_content.child("item").attribute("automation").set_value(auto_t.c_str());
            }
            if (temp_t){
                for (auto& node : xml_content.child("item").children())
                {
                    if (strcmp(node.attribute("name").value() , automation.c_str()) == 0)
                    {
                        node.attribute("temperature-level").set_value(temp_t);;
                    }
                }
            }
            set_auto();
            stringstream xml;
            xml_content.print(xml);
            handler(state_len, addr, state);
        }

};

class Dimmer : public Device {
    public:
        string automation;
        const static int state_len = 2;

        Dimmer(const pugi::xml_node& node, const string addr, const string type, Shclient& shc) : Device(node, addr, type, shc) {}

        void print_state(){
            printf("Power: %d Brs: %d\n", state[0], (int)round(static_cast<double>(state[1]) / 2.5));
            cout << endl;
        };
    };

class Rgb : public Device {
    public:
        string automation;
        const static int state_len = 4;

        Rgb(const pugi::xml_node& node, const string addr, const string type, Shclient& shc) : Device(node, addr, type, shc) {}

        void print_state(){
            printf("Power: %d Brs: %d Sat: %d Hue: %d\n", state[0], (int)round(static_cast<double>(state[1]) / 2.5), (int)round(static_cast<double>(state[2]) / 2.5), (int)round(static_cast<double>(state[3]) / 2.5));
            cout << endl;
        }
};
