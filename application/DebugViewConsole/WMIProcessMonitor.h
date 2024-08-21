#pragma once
#include <functional>
#include <string>
#include <memory>
#include <wbemidl.h>
#include <comdef.h>

namespace WMI {
struct ProcessMonitor
{
    ProcessMonitor(bool handleCtrlC=false);
    ~ProcessMonitor();

    void (*getCleanup())(ProcessMonitor&)
    {
        return cleanup;
    }

    static ProcessMonitor& getInstance();

    void monitorProcessStartStop(std::function<void(std::string&, DWORD pid, bool)> cb, std::function<bool()> stop);

private:
    bool handleCtrlC{false};
    std::unique_ptr<IWbemLocator> loc{};
    std::unique_ptr<IWbemServices> svc{};
    std::unique_ptr<IEnumWbemClassObject> enumerator{};
    bool cleaned{false};

    static void cleanup(WMI::ProcessMonitor& wmip);
};

struct WMIException : std::exception
{
protected:
    const char* wmiPrefix{"WMI"};
};

struct ProcessMonitorExc : WMIException
{
protected:
    const char* exceptionPrefix{"WMIProcessMonitor: "};
};

struct ProcessMonitorFailedToInitializeCom : ProcessMonitorExc
{
    const char* what() const noexcept override
    {
        msg += "Failed to initialize com";
        return msg.c_str();
    }

private:
    mutable std::string msg{ProcessMonitorExc::exceptionPrefix};
};

struct ProcessMonitorFailedToInitializeSecurity : ProcessMonitorExc
{
    const char* what() const noexcept override
    {
        msg += "Failed to initialize security";
        return msg.c_str();
    }

private:
    mutable std::string msg{ProcessMonitorExc::exceptionPrefix};
};

struct ProcessMonitorFailedToCreateIWbemLocator : ProcessMonitorExc
{
    const char* what() const noexcept override
    {
        msg += "Failed to create IWbemLocator";
        return msg.c_str();
    }

private:
    mutable std::string msg{ProcessMonitorExc::exceptionPrefix};
};

struct ProcessMonitorFailedToSetProxyBlanket : ProcessMonitorExc
{
    const char* what() const noexcept override
    {
        msg += "Failed to set proxy blanket";
        return msg.c_str();
    }

private:
    mutable std::string msg{ProcessMonitorExc::exceptionPrefix};
};

struct ProcessMonitorFailedQueryForProcessCreationEvents : ProcessMonitorExc
{
    const char* what() const noexcept override
    {
        msg += "Failed query for process creation events";
        return msg.c_str();
    }

private:
    mutable std::string msg{ProcessMonitorExc::exceptionPrefix};
};
} // namespace WMI
