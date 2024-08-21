#include <iostream>
#include <csignal>
#include <windows.h>
#include "WMIProcessMonitor.h"

#pragma comment(lib, "wbemuuid.lib")

namespace WMI {
static void signalHandler(int signum);

ProcessMonitor::ProcessMonitor(bool handleCtrlC)
{
    if (handleCtrlC)
    {
        // Register signal handler for Ctrl+C
        signal(SIGINT, signalHandler);
    }

    HRESULT hres{CoInitializeEx(0, COINIT_MULTITHREADED)};
    if (FAILED(hres))
    {
        throw WMI::ProcessMonitorFailedToInitializeCom{};
    }

    // Set general COM security levels.
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates service.
        NULL,                        // Authentication services.
        NULL,                        // Reserved.
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication.
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation.
        NULL,                        // Authentication info.
        EOAC_NONE,                   // Additional capabilities.
        NULL                         // Reserved.
    );
    if (FAILED(hres))
    {
        CoUninitialize();
        throw WMI::ProcessMonitorFailedToInitializeSecurity{};
    }

    // Obtain the initial locator to WMI.
    IWbemLocator* loc_{nullptr};
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&loc_);
    if (FAILED(hres))
    {
        CoUninitialize();
        throw WMI::ProcessMonitorFailedToInitializeSecurity{};
    }
    else
    {
        loc.reset(loc_);
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method.
    IWbemServices* svc_{nullptr};
    hres = loc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &svc_);
    if (FAILED(hres))
    {
        ProcessMonitor::cleanup(*this);
        throw WMI::ProcessMonitorFailedToCreateIWbemLocator{};
    }
    else
    {
        svc.reset(svc_);
    }

    // Set security levels on the proxy.
    hres = CoSetProxyBlanket(
        svc.get(),
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);
    if (FAILED(hres))
    {
        ProcessMonitor::cleanup(*this);
        throw WMI::ProcessMonitorFailedToSetProxyBlanket{};
    }

    // Use WMI to query for new process creation events.
    IEnumWbemClassObject* enum_{nullptr};
    hres = svc->ExecNotificationQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM __InstanceOperationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &enum_);
    if (FAILED(hres))
    {
        ProcessMonitor::cleanup(*this);
        throw WMI::ProcessMonitorFailedQueryForProcessCreationEvents{};
    }
    else
    {
        enumerator.reset(enum_);
    }
}

void ProcessMonitor::monitorProcessStartStop(std::function<void(std::string&, DWORD pid, bool)> cb, std::function<bool()> stop)
{
    IWbemClassObject* pclsObj{nullptr};
    auto uReturn{0UL};

    while (!stop())
    {
        if (enumerator == nullptr) return;
        HRESULT err{enumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)};

        if (err == WBEM_S_NO_ERROR && uReturn != 0)
        {
            VARIANT vtProp;
            err = pclsObj->Get(L"TargetInstance", 0, &vtProp, 0, 0);
            if (SUCCEEDED(err))
            {
                IWbemClassObject* pclsObjInner = nullptr;
                err = vtProp.punkVal->QueryInterface(IID_IWbemClassObject, (void**)&pclsObjInner);
                if (SUCCEEDED(err))
                {
                    VARIANT vtName;
                    VARIANT vtPid;
                    VARIANT vtEventType;
                    err = pclsObj->Get(L"__Class", 0, &vtEventType, 0, 0);
                    auto err_inner{pclsObjInner->Get(L"Name", 0, &vtName, 0, 0)};
                    err_inner = pclsObjInner->Get(L"ProcessId", 0, &vtPid, 0, 0); // Retrieve the PID
                    if (SUCCEEDED(err) && SUCCEEDED(err_inner))
                    {
                        auto nameStr{reinterpret_cast<wchar_t*>(vtName.bstrVal)};
                        auto length{wcsnlen(nameStr, 256)};
                        std::wstring processNameW(nameStr, nameStr + length);
                        std::string processName(processNameW.begin(), processNameW.end());

                        if (wcscmp(vtEventType.bstrVal, L"__InstanceCreationEvent") == 0)
                        {
                            cb(processName, vtPid.uintVal, true);
                        }
                        else if (wcscmp(vtEventType.bstrVal, L"__InstanceDeletionEvent") == 0)
                        {
                            cb(processName, vtPid.uintVal, false);
                        }
                        VariantClear(&vtName);
                        VariantClear(&vtEventType);
                    }
                    pclsObjInner->Release();
                }
                VariantClear(&vtProp);
            }
            pclsObj->Release();
        }
    }
}

ProcessMonitor::~ProcessMonitor()
{
    cleanup(*this);
}

void ProcessMonitor::cleanup(ProcessMonitor& wmip)
{
    // Properly release WMI and COM resources
    if (wmip.enumerator)
    {
        wmip.enumerator->Release();
        wmip.enumerator.release();
    }
    if (wmip.svc)
    {
        wmip.svc->Release();
        wmip.svc.release();
    }
    if (wmip.loc)
    {
        wmip.loc->Release();
        wmip.loc.release();
    }
    CoUninitialize();
}

static void signalHandler(int signum)
{
    auto& wmip{WMI::ProcessMonitor::getInstance()};

    wmip.getCleanup()(WMI::ProcessMonitor::getInstance());

    exit(signum);
}

static ProcessMonitor wmipm{};

ProcessMonitor& ProcessMonitor::getInstance()
{
    return wmipm;
}
} // namespace WMI
