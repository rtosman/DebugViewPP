// (C) Copyright Gert-Jan de Vos and Jan Wilmans 2013.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <windows.h>
#include <dbghelp.h>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <memory>
#include <algorithm>
#include <functional>
#include <thread>
#include <boost/asio.hpp>
#include "Win32/Utilities.h"
#include "CobaltFusion/scope_guard.h"
#include "CobaltFusion/Str.h"
#include "CobaltFusion/ExecutorClient.h"
#include "CobaltFusion/Executor.h"
#include "DebugViewppLib/DBWinBuffer.h"
#include "DebugViewppLib/DBWinReader.h"
#include "DebugViewppLib/FileIO.h"
#include "DebugViewppLib/ProcessInfo.h"
#include "DebugViewppLib/LogSources.h"
#include "DebugViewppLib/Conversions.h"
#include "DebugViewppLib/LineBuffer.h"
#include "../DebugViewpp/version.h"

#include "DebugViewppLib/Filter.h"
#include "DebugViewppLib/LogFile.h"

#include "cxxopts.hpp"

#include "pugixml.hpp"
#include <Windows.h>
#include <TlHelp32.h>
#include "WMIProcessMonitor.h"

namespace fusion {
namespace debugviewpp {

struct Ban
{
    std::wstring                                        processNameW;
    std::string                                         processName;
    std::vector<std::string>                            bannedEmissions;
    std::chrono::time_point<std::chrono::steady_clock>  time_of_start;

    Ban(const char* name)
    {
        auto len{strnlen(name, 256)};

        processName = std::string(name, name+len);
        processNameW = std::wstring(processName.begin(), processName.end());

        time_of_start = std::chrono::steady_clock::now();
    }
};

struct Settings
{
    using Initializer = std::function<void(fusion::debugviewpp::Settings&, std::vector<Ban>&)>;
    bool timestamp;
    bool performanceCounter;
    bool tabs;
    bool pid;
    bool processName;
    bool autonewline;
    bool flush;
    bool linenumber;
    bool console;
    bool verbose;
    bool go{false};
    bool stop{false};
    std::string filename;
    std::vector<std::string> include;
    std::vector<std::string> exclude;
    std::vector<std::string> includeprocesses;
    std::vector<std::string> excludeprocesses;
    std::vector<Ban>         bans;
    static std::mutex bans_lock;
    std::string quitmessage;
    std::unique_ptr<std::thread> thread;

    Settings(Initializer init_bans)
    {
        init_bans(*this, bans);
        go = true;
    }

    std::mutex& getBansLock() const
    {
        return bans_lock;
    }
    void lockBans()
    {
        bans_lock.lock();
    }
    void unlockBans()
    {
        bans_lock.unlock();
    }
};

std::mutex Settings::bans_lock;

struct PidSettings
{
    fusion::debugviewpp::Ban& ban;
    DWORD pid{};

    PidSettings(fusion::debugviewpp::Ban& b, DWORD p)://, fusion::debugviewpp::Settings& s) :
        ban{b},
        pid{p}
    {
    }

    PidSettings& operator=(const PidSettings& other)
    {
        ban = other.ban;
        pid = other.pid;
        return *this;
    }

    // Move constructor (defaulted for simplicity)
    PidSettings(PidSettings&& other):
        ban{other.ban},
        pid{other.pid}
    {
    }

    // Copy constructor (defaulted for simplicity)
    PidSettings(const PidSettings&) = default;

    ~PidSettings()
    {
    }
};

std::mutex pid_binding_mutex{};
static std::vector<PidSettings> pid_binding;

static Win32::Handle g_quitMessageHandle;

bool ContainsText(const std::string& line, const std::string& message)
{
    if (message.empty())
        return false;
    return line.find(message) != std::string::npos;
}

bool IsEventSet(Win32::Handle& handle)
{
    return Win32::WaitForSingleObject(handle, 0);
}

void AddMessageFilter(LogFilter& filter, FilterType::type filterType, const std::string pattern)
{
    auto bgColor = COLORREF();
    auto fgColor = COLORREF();
    filter.messageFilters.push_back(Filter(pattern, MatchType::Simple, filterType, bgColor, fgColor));
}

void AddProcessFilter(LogFilter& filter, FilterType::type filterType, const std::string pattern)
{
    auto bgColor = COLORREF();
    auto fgColor = COLORREF();
    filter.processFilters.push_back(Filter(pattern, MatchType::Simple, filterType, bgColor, fgColor));
}

bool IsIncluded(LogFilter& filter, const Line& line)
{
    MatchColors matchcolors; //  not used on the command-line
    return IsIncluded(filter.processFilters, line.processName, matchcolors) && IsIncluded(filter.messageFilters, line.message, matchcolors);
}

void OutputDetails(const Settings& settings,const Line& line)
{
    std::string separator{settings.tabs ? "\t" : " "};
    if (settings.timestamp)
    {
        std::cout << fusion::debugviewpp::GetTimeText(line.systemTime) << separator;
    }
    if (settings.performanceCounter)
    {
        std::cout << fusion::debugviewpp::GetTimeText(line.time) << separator;
    }
    if (settings.pid)
    {
        std::cout << line.pid << separator;
        if (pid_binding.size())
        {
            auto is_banned_pid = [&line](std::string& processName) -> bool
            {
                std::scoped_lock lock(fusion::debugviewpp::pid_binding_mutex);
                auto it{std::find_if(pid_binding.begin(),
                                         pid_binding.end(),
                                         [&line, &processName](PidSettings& binding)
                                         {
                                            if (line.pid == binding.pid)
                                            {
                                                processName = binding.ban.processName;
                                                return true;
                                            }
                                            return false;
                                         }
                                    )
                    };
                    return it != pid_binding.end();
            };

            std::string process_name;
            if (is_banned_pid(process_name))
            {
                std::cerr << "Banned emission from " << process_name << " (" << line.pid << "): " << line.message << "\n";
            }
        }
    }
    if (settings.processName)
    {
        std::cout << line.processName.c_str() << separator;
    }
}

void LogMessages(Settings& settings)
{
    using namespace std::chrono_literals;
    LogFilter filter;
    ActiveExecutorClient executor;
    LogSources logsources(executor);
    executor.Call([&] {
        logsources.AddDBWinReader(false);
        if (IsWindowsVistaOrGreater() && HasGlobalDBWinReaderRights())
            logsources.AddDBWinReader(true);
        logsources.SetAutoNewLine(settings.autonewline);
    });

    if (settings.bans.size())
    {
        std::scoped_lock lock(settings.getBansLock());
        for (auto ban : settings.bans)
        {
            AddProcessFilter(filter, FilterType::Include, ban.processName);

            for (auto emission : ban.bannedEmissions)
            {
                AddMessageFilter(filter, FilterType::Include, emission);
            }
        }
    }

    for (const auto& value : settings.include)
    {
        AddMessageFilter(filter, FilterType::Include, value);
    }

    for (const auto& value : settings.exclude)
    {
        AddMessageFilter(filter, FilterType::Exclude, value);
    }

    for (const auto& value : settings.includeprocesses)
    {
        AddProcessFilter(filter, FilterType::Include, value);
    }

    for (const auto& value : settings.excludeprocesses)
    {
        AddProcessFilter(filter, FilterType::Exclude, value);
    }

    std::ofstream fs;
    if (!settings.filename.empty())
    {
        OpenLogFile(fs, WStr(settings.filename));
        fs.flush();
    }

    auto guard = make_guard([&fs, &settings]() {
        if (!settings.filename.empty())
        {
            fs.flush();
            fs.close();
            std::cout << "Log file closed.\n";
        }
    });

    std::string_view separator{settings.tabs ? "\t" : " "};
    while (!settings.stop && (!IsEventSet(g_quitMessageHandle)))
    {
        Lines lines;
        executor.Call([&] {
            lines = logsources.GetLines();
        });

        int linenumber = 0;
        for (const auto& line : lines)
        {
            if (ContainsText(line.message, settings.quitmessage))
            {
                settings.stop = true;
                break;
            }

            if (!debugviewpp::IsIncluded(filter, line))
                continue;

            if (settings.console)
            {
                if (settings.linenumber)
                {
                    ++linenumber;
                    std::cout << std::setw(5) << std::setfill('0') << linenumber << std::setfill(' ') << separator;
                }
                OutputDetails(settings, line);
                std::cout << separator << line.message.c_str() << "\n";
            }
            if (!settings.filename.empty())
            {
                WriteLogFileMessage(fs, line.time, line.systemTime, line.pid, line.processName, line.message);
            }
        }
        if (settings.flush)
        {
            std::cout.flush();
            fs.flush();
        }
        std::this_thread::sleep_for(50ms);
    }
    std::cout.flush();
}

} // namespace debugviewpp
} // namespace fusion

char* getCmdOption(char** begin, char** end, const std::string& option)
{
    char** itr = std::find(begin, end, option);
    return itr != end && ++itr != end ? *itr : nullptr;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}

fusion::debugviewpp::Settings* global_settings_ptr{nullptr};

BOOL WINAPI ConsoleHandler(DWORD dwType)
{

    switch (dwType)
    {
    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (global_settings_ptr)
        {
            global_settings_ptr->stop = true;
        }
        // report as handled, so no other handler gets called.
        return TRUE;
    default:
        break;
    }
    return FALSE;
}

static bool processInBans(const fusion::debugviewpp::Settings& settings, const std::string_view& processName)
{
    std::scoped_lock lock(settings.getBansLock());
    return std::find_if(settings.bans.begin(),
               settings.bans.end(),
               [&processName](auto& ban) {
                   return (ban.processName.find(processName) != std::string::npos);
               }) != settings.bans.end();
};

void registerProcessForNotification(fusion::debugviewpp::Ban& ban, fusion::debugviewpp::Settings& settings)
{
    using namespace std::chrono_literals;
    if (!settings.thread)
    {
        auto& wmipm{WMI::ProcessMonitor::getInstance()};
        settings.thread = std::make_unique<std::thread>([&wmipm, &settings, &ban]()
                                            {
                                                while (!settings.go)
                                                {
                                                    std::this_thread::sleep_for(10ms);
                                                }

                                                wmipm.monitorProcessStartStop([&ban, &settings](std::string& processName, DWORD pid, bool isStart)
                                                {
                                                    if(settings.stop) return;

                                                    if (isStart)
                                                    {
                                                        if (!processInBans(settings, processName))
                                                        {
                                                            return;
                                                        }
                                                        std::scoped_lock lock(fusion::debugviewpp::pid_binding_mutex);
                                                        fusion::debugviewpp::pid_binding.emplace_back(ban, pid);
                                                    }
                                                    else
                                                    {
                                                        std::scoped_lock lock(fusion::debugviewpp::pid_binding_mutex);
                                                        // locate the process ban entry by name
                                                        auto bind_it{
                                                            std::find_if(fusion::debugviewpp::pid_binding.begin(),
                                                                fusion::debugviewpp::pid_binding.end(),
                                                                [&settings, &processName](auto& binding) {
                                                                    return (binding.ban.processName.find(processName) != std::string::npos);
                                                                })};
                                                        if (bind_it != fusion::debugviewpp::pid_binding.end())
                                                        {
                                                            auto& binding{*bind_it};
                                                            auto current_time{std::chrono::steady_clock::now()};
                                                            auto duration{std::chrono::duration_cast<std::chrono::milliseconds>(current_time - binding.ban.time_of_start)};
                                                            std::cout << "Process (" << processName << ") with PID " << binding.pid << " terminated after : " << duration << " ms\n ";
                                                            binding.ban.time_of_start = std::chrono::steady_clock::now();
                                                            fusion::debugviewpp::pid_binding.erase(bind_it);
                                                        }
//                                                        else
//                                                        {
//                                                            std::cout << "Process with PID " << processName << " terminated without a located ban\n";
//                                                        }
                                                    }
                                                },
                                                [&settings]() -> bool
                                                {
                                                    return settings.stop;
                                                }
                                         );
        });
    }
}
/*
static const char USAGE[] =
    R"(DebugviewConsole )" VERSION_STR
    R"(
    Usage:
        DebugviewConsole [-acflsqtpnv] [-d <file>] [-i <pattern>]... [-e <pattern>]... [-m <message>] [--include-process <pattern>]... [--exclude-process <pattern>]...
        DebugviewConsole (-h | --help)
        DebugviewConsole [-x]
        DebugviewConsole [-u]

    Options:
        -h, --help                          show this screen
        -i <pattern>, --include <pattern>   include filter, may be specified multiple times
        -e <pattern>, --exclude <pattern>   exclude filter, may be specified multiple times
        --include-process <pattern>         include filter for process names
        --exclude-process <pattern>         exclude filter for process names
        -a              auto-newline, most people want this
        -c              enable console output
        -v              verbose
        -d <file>       write to .dblog file

    Console options:    (no effect on .dblog file)
        -l              prefix line number
        -s              prefix messages with system time
        -q              prefix message with high-precision (<1us) offset from QueryPerformanceCounter
        -t              tab-separated output
        -p              add PID (process ID)
        -n              add process name

    Advanced options:
        -f              aggressively flush buffers, if unsure, do not use
        -x              stop all running debugviewconsole instances
        -u              send a UDP test-message, used only for debugging
        -m <message>, --quit-message <message>  if this message is received the application exits
)";
*/

fusion::debugviewpp::Settings& CreateSettings(const cxxopts::ParseResult& result, std::string_view&& debugctrl)
{
    static auto settings{fusion::debugviewpp::Settings([&debugctrl](fusion::debugviewpp::Settings& settings, std::vector<fusion::debugviewpp::Ban>& bans) -> void
                                                        {
                                                            pugi::xml_document      doc{};
                                                            pugi::xml_parse_result  result{doc.load_file(debugctrl.data())};
                                                            pugi::xml_node          banlist{doc.child("ban_list")};

                                                            std::scoped_lock lock(settings.getBansLock());
                                                            for (auto ban : banlist.children("process"))
                                                            {
                                                                bans.emplace_back(ban.attribute("name").value());
                                                                auto& b{bans.back()};

                                                                for (auto emission : ban.child("banned_emissions_list").children("banned_emission"))
                                                                {
                                                                    b.bannedEmissions.emplace_back(emission.child_value());
                                                                }
                                                                registerProcessForNotification(b, settings);
                                                            }
                                                        }
                                                      )
    };

    settings.filename = result.count("file") ? result["file"].as<std::string>() : "";
    settings.autonewline = result["a"].as<bool>();
    settings.flush = result["f"].as<bool>();
    settings.console = result["c"].as<bool>();
    settings.verbose = result["v"].as<bool>();
    settings.linenumber = result["l"].as<bool>();
    settings.timestamp = result["s"].as<bool>();
    settings.performanceCounter = result["q"].as<bool>();
    settings.tabs = result["t"].as<bool>();
    settings.pid = result["p"].as<bool>();
    settings.processName = result["n"].as<bool>();
    settings.include = result.count("include") ? result["include"].as<std::vector<std::string>>() : std::vector<std::string>();
    settings.exclude = result.count("exclude") ? result["exclude"].as<std::vector<std::string>>() : std::vector<std::string>();
    settings.includeprocesses = result.count("include-process") ? result["include-process"].as<std::vector<std::string>>() : std::vector<std::string>();
    settings.excludeprocesses = result.count("exclude-process") ? result["exclude-process"].as<std::vector<std::string>>() : std::vector<std::string>();
    settings.quitmessage = result.count("quit-message") ? result["quit-message"].as<std::string>() : "";

    return settings;
}


int main(int argc, char* argv[])
try
{
    using namespace fusion::debugviewpp;
    //    const auto args = docopt::docopt(USAGE, {argv + 1, argv + argc}, true, "DebugviewConsole " VERSION_STR);
    cxxopts::Options options("DebugviewConsole", "VERSION_STR\nDebugviewConsole");
    options.add_options()("h,help","Show this screen")
                         ("a", "Auto-newline, most people want this")
                         ("c", "Enable console output")
                         ("v", "Verbose")
                         ("b,ban", "Ban file name", cxxopts::value<std::string>()->default_value("./debugctrl.xml"))
                         ("d,dblog", "Write to .dblog file", cxxopts::value<std::string>())
                         ("i,include", "Include filter, may be specified multiple times", cxxopts::value<std::vector<std::string>>())
                         ("e,exclude", "Exclude filter, may be specified multiple times", cxxopts::value<std::vector<std::string>>())
                         ("include-process", "Include filter for process names", cxxopts::value<std::vector<std::string>>())
                         ("exclude-process", "Exclude filter for process names", cxxopts::value<std::vector<std::string>>())
                         ("l", "Prefix line number")("s", "Prefix messages with system time")
                         ("q", "Prefix message with high-precision (<1us) offset from QueryPerformanceCounter")
                         ("t", "Tab-separated output")
                         ("p", "Add PID (process ID)")
                         ("n", "Add process name")
                         ("f", "Aggressively flush buffers, if unsure, do not use")
                         ("x", "Stop all running debugviewconsole instances")
                         ("u", "Send a UDP test-message, used only for debugging")
                         ("m,quit-message", "If this message is received the application exits", cxxopts::value<std::string>());
    auto result{options.parse(argc, argv)};
    if (result.count("help"))
    {
        std::cout << options.help() << std::endl;
        return 0;
    }
    auto& settings{CreateSettings(result, result["b"].as<std::string>())};
    global_settings_ptr = &settings;
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE))
    {
        std::cerr << "Could not set control handler." << std::endl;
        return 0;
    }

    std::cout << "DebugViewConsole " << VERSION_STR << std::endl;
    g_quitMessageHandle = fusion::Win32::CreateEvent(nullptr, true, false, L"DebugViewConsoleQuitEvent");
    if (result.count("x") ? result["x"].as<bool>() : false)
    {
        if (settings.verbose)
            std::cout << "-x: sending terminate signal to all DebugViewConsole instances\n";
        SetEvent(g_quitMessageHandle);
        return 0;
    }

    if (result.count("u") ? result["u"].as<bool>() : false)
    {
        std::string msg = argv[2];
        msg += "\n";
        std::cout << "Broadcast to 255.255.255.255 on UDP port 2020, message: " << msg;
        using namespace boost::asio::ip;
        boost::asio::io_service io_service;
        udp::resolver resolver(io_service);
        udp::resolver::query query(udp::v4(), "255.255.255.255", "2020");
        udp::endpoint receiver_endpoint = *resolver.resolve(query);
        udp::socket socket(io_service);
        socket.open(udp::v4());

        // enable broadcast
        boost::asio::socket_base::broadcast option(true);
        socket.set_option(option);

        socket.send_to(boost::asio::buffer(msg), receiver_endpoint);
        std::cout << "Done." << std::endl;
        return 0;
    }

    if (settings.filename.empty() && settings.console == false)
    {
        std::cout << "Neither output to logfile or console was specified, nothing to do...\n";
        return 1;
    }

    std::cout << "Listening for OutputDebugString messages..." << std::endl;
    LogMessages(settings);
    settings.thread->join();
    std::cout << "Process ended normally.\n";
    return 0;
}
catch (std::exception& e)
{
    std::cerr << "Unexpected error occurred: " << e.what() << std::endl;
    std::string message(e.what());
    if (message.find("CreateDBWinBufferMapping") != std::string::npos)
    {
        std::cerr << "Another DebugView++ (or similar application) might be running. " << std::endl;
    }
    return 1;
}
