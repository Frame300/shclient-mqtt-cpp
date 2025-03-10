#include "devices.hpp"
#include "Shclient.hpp"


class Factory {
private:
    std::unordered_map<std::string, std::unique_ptr<Device>> devices;
    Shclient* shc;

    void parse_area(const pugi::xml_node& area_node) {
        for (const auto& node : area_node.children()) {
            if (strcmp(node.name(), "area") == 0) {
                // Рекурсивный обход вложенных областей
                parse_area(node);
            } else if (strcmp(node.name(), "item") == 0) {
                string addr = node.attribute("addr").as_string();
                string type = node.attribute("type").as_string();
                if (type == "valve-heating") {
                    unique_ptr<Device> dev(new Heating(node, addr, type, *shc));
                    devices.emplace(addr, std::move(dev));
                } else if (type == "dimer-lamp" || type == "dimmer-lamp") {
                    unique_ptr<Device> dev(new Dimmer(node, addr, type, *shc));
                    devices.emplace(addr, std::move(dev));
                } else if (type == "rgb-lamp") {
                    unique_ptr<Device> dev(new Rgb(node, addr, type, *shc));
                    devices.emplace(addr, std::move(dev));
                } else {
                    unique_ptr<Device> dev(new Device(node, addr, type, *shc));
                    devices.emplace(addr, std::move(dev));
                }
                
            }
        }
    }

public:

    Factory(Shclient& shc) : shc(&shc){}

    bool load_from_xml(const string& logicXml) {
        pugi::xml_document doc;
        if (!doc.load_string(logicXml.c_str())) return false;
        
        const auto root = doc.child("smart-house");
        devices.clear();
        for (const auto& area : root.children("area")) {
            parse_area(area);
        }
        return true;
    }

    unique_ptr<Device>* get_device(const string& addr) {
        auto it = devices.find(addr);
        return it != devices.end() ? &it->second : nullptr;
    }
};
