#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
using namespace std;
namespace fs = std::filesystem;

// Enum to represent log levels
enum LogLevel { DEBUG, INFO, WARNING, ERROR, CRITICAL };

class Logger {
public:
    LogLevel Level = DEBUG;
    size_t maxFileSize = 1024*1024; // Максимальный размер файла лога (1 MB)
    size_t maxFiles = 5; // Максимальное количество файлов лога
    int8_t check_c = 0;

    // Constructor: Opens the log file in append mode
    Logger(const string& filename)
        : logFileName(filename)
    {
        openLogFile();
    }

    void setLevel(LogLevel level)
    {
        Level = level;
    }

    void setMaxFileSize(size_t size)
    {
        maxFileSize = size;
    }

    void setMaxFiles(size_t count)
    {
        maxFiles = count;
    }

    // Destructor: Closes the log file
    ~Logger() { logFile.close(); }

    // Logs a message with a given log level
    void log(LogLevel level, const string& message)
    {
        if (level < Level) return;
        // Get current timestamp
        time_t now = time(0);
        tm* timeinfo = localtime(&now);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp),
                 "%Y-%m-%d %H:%M:%S", timeinfo);

        // Create log entry
        ostringstream logEntry;
        logEntry << "[" << timestamp << "] "
                 << levelToString(level) << ": " << message
                 << endl;

        // Output to console
        cout << logEntry.str();

        // Output to log file
        if (logFile.is_open()) {
            logFile << logEntry.str();
            logFile.flush(); // Ensure immediate write to file
            check_c++;
            if (check_c > 100) {
                check_c = 0;
                if (logFile.tellp() >= maxFileSize) rotateLogFiles();
            }
        }
    }

private:
    ofstream logFile; // File stream for the log file
    string logFileName; // Имя файла лога

    // Converts log level to a string for output
    string levelToString(LogLevel level)
    {
        switch (level) {
        case DEBUG:
            return "DEBUG";
        case INFO:
            return "INFO";
        case WARNING:
            return "WARNING";
        case ERROR:
            return "ERROR";
        case CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
        }
    }

    void openLogFile()
    {
        logFile.open(logFileName, ios::app);
        if (!logFile.is_open()) {
            cerr << "Error opening log file." << endl;
        }
    }

    void rotateLogFiles()
    {
        logFile.close();
        for (int i = maxFiles - 1; i > 0; --i) {
            string oldName = logFileName + "." + to_string(i);
            string newName = logFileName + "." + to_string(i + 1);
            if (fs::exists(oldName)) {
                fs::rename(oldName, newName);
            }
        }
        fs::rename(logFileName, logFileName + ".1");
        openLogFile();
        deleteOldLogFiles();
    }

    void deleteOldLogFiles()
    {
        string oldLogFile = logFileName + "." + to_string(maxFiles);
        if (fs::exists(oldLogFile)) {
            fs::remove(oldLogFile);
        }
    }
};
