#include <windows.h>
#include <string>

const char g_szClassName[] = "PasswordManagerWindow";

// Forward declarations
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSEX wc = { };
    HWND hwnd;
    MSG Msg;

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = g_szClassName;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    RegisterClassEx(&wc);

    hwnd = CreateWindowEx(
        0,
        g_szClassName,
        "Simple Password Manager",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 400,
        nullptr, nullptr, hInstance, nullptr);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&Msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }

    return static_cast<int>(Msg.wParam);
}

void ShowAddEntryDialog(HWND parent)
{
    MessageBox(parent, "Add Entry functionality will go here.", "Add Entry", MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND hAddButton;

    switch (msg)
    {
    case WM_CREATE:
        hAddButton = CreateWindow(
            "BUTTON", "Add Entry",
            WS_VISIBLE | WS_CHILD,
            10, 10, 100, 30,
            hwnd, (HMENU)1, ((LPCREATESTRUCT)lParam)->hInstance, nullptr);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            ShowAddEntryDialog(hwnd);
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    return 0;
}
