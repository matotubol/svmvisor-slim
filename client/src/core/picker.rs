//! A native Win32 process picker.
//!
//! The window's only job is to choose a process from the kernel's list. It closes once a process
//! is double-clicked, and the caller reads that process; there is no on-screen memory view.

use std::{cell::RefCell, ffi::c_void, iter, mem, ptr};

use svmvisor_live_reader::{Config, ProcessEntry, Result, Svm};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
    System::LibraryLoader::GetModuleHandleW,
    UI::WindowsAndMessaging::{
        CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        GetClientRect, GetMessageW, IDC_ARROW, LB_ADDSTRING, LB_ERR, LB_GETCURSEL, LBN_DBLCLK,
        LBS_HASSTRINGS, LBS_NOTIFY, LoadCursorW, MSG, MoveWindow, PostQuitMessage, RegisterClassW,
        SW_SHOW, SendMessageW, ShowWindow, TranslateMessage, UnregisterClassW, WM_COMMAND,
        WM_DESTROY, WM_SIZE, WNDCLASSW, WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
        WS_VSCROLL,
    },
};

use crate::{process::Process, runtime};

/// The listbox's control id inside the picker window.
const LIST_ID: usize = 1;

/// The window procedure's state: how many processes are listed, the listbox handle, and the
/// chosen index.
struct Pick {
    processes: usize,
    listbox: HWND,
    chosen: Option<usize>,
}

thread_local! {
    static PICK: RefCell<Pick> =
        const { RefCell::new(Pick { processes: 0, listbox: ptr::null_mut(), chosen: None }) };
}

/// Connects, lists the processes in a window and opens the one double-clicked; `None` when the
/// window closes without a choice. A failed connection or listing still opens the window, showing
/// why, and is returned once it closes.
/// Live access is currently disabled, so the window displays `ReaderDisabled`.
pub fn pick(config: Config) -> Result<Option<Process>> {
    let mut svm = runtime::connect(config);
    let listed = svm.as_mut().map_err(|error| error.clone()).and_then(Svm::list_processes);
    let chosen = match &listed {
        Ok(processes) => {
            choose(processes, &format!("{} processes — double-click to read", processes.len()))
        }
        Err(error) => choose(&[], &error.to_string()),
    };
    listed?;
    chosen.map(|entry| Process::new(svm?, entry)).transpose()
}

/// Shows the modal picker and returns the double-clicked process, or `None` if the window closed.
/// The window always opens; when the list is empty, `status` explains why.
fn choose(processes: &[ProcessEntry], status: &str) -> Option<ProcessEntry> {
    PICK.with(|pick| {
        let mut pick = pick.borrow_mut();
        pick.processes = processes.len();
        pick.chosen = None;
    });

    // SAFETY: every handle is checked before use, the window class is unregistered before
    // returning, and the whole picker runs on this one thread with the window procedure.
    let index = unsafe { show(processes, status) };
    index.and_then(|index| processes.get(index).cloned())
}

unsafe fn show(processes: &[ProcessEntry], status: &str) -> Option<usize> {
    unsafe {
        let instance = GetModuleHandleW(ptr::null());
        let class = wide("SvmVisorPicker");
        let window_class = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(procedure),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance.cast(),
            hIcon: ptr::null_mut(),
            hCursor: LoadCursorW(ptr::null_mut(), IDC_ARROW),
            hbrBackground: (16isize) as *mut c_void, // COLOR_BTNFACE + 1
            lpszMenuName: ptr::null(),
            lpszClassName: class.as_ptr(),
        };
        if RegisterClassW(&window_class) == 0 {
            return None;
        }

        let title = wide("SVMVisor · Select a process");
        let window = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            380,
            520,
            ptr::null_mut(),
            ptr::null_mut(),
            instance.cast(),
            ptr::null(),
        );
        if window.is_null() {
            UnregisterClassW(class.as_ptr(), instance.cast());
            return None;
        }

        let list_class = wide("LISTBOX");
        let style = WS_CHILD
            | WS_VISIBLE
            | WS_VSCROLL
            | WS_BORDER
            | LBS_NOTIFY as u32
            | LBS_HASSTRINGS as u32;
        let listbox = CreateWindowExW(
            0,
            list_class.as_ptr(),
            ptr::null(),
            style,
            0,
            0,
            0,
            0,
            window,
            LIST_ID as *mut c_void,
            instance.cast(),
            ptr::null(),
        );
        PICK.with(|pick| pick.borrow_mut().listbox = listbox);

        // The list rows, or the reason there are none, so the window is never blank.
        if processes.is_empty() {
            add_row(listbox, status);
        } else {
            for process in processes {
                add_row(listbox, &format!("{:>7}  {}", process.pid, process.name));
            }
        }
        fit_listbox(window, listbox);

        ShowWindow(window, SW_SHOW);

        let mut message: MSG = mem::zeroed();
        while GetMessageW(&mut message, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        let chosen = PICK.with(|pick| pick.borrow().chosen);
        UnregisterClassW(class.as_ptr(), instance.cast());
        chosen
    }
}

unsafe fn add_row(listbox: HWND, text: &str) {
    let row = wide(text);
    unsafe { SendMessageW(listbox, LB_ADDSTRING, 0, row.as_ptr() as LPARAM) };
}

/// Sizes the listbox to fill the window's client area.
unsafe fn fit_listbox(window: HWND, listbox: HWND) {
    unsafe {
        let mut rect: RECT = mem::zeroed();
        if GetClientRect(window, &mut rect) != 0 {
            MoveWindow(listbox, 0, 0, rect.right - rect.left, rect.bottom - rect.top, 1);
        }
    }
}

unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match message {
            WM_SIZE => {
                let listbox = PICK.with(|pick| pick.borrow().listbox);
                if !listbox.is_null() {
                    MoveWindow(listbox, 0, 0, loword(lparam as u32), hiword(lparam as u32), 1);
                }
                0
            }
            WM_COMMAND
                if loword(wparam as u32) as usize == LIST_ID
                    && hiword(wparam as u32) as u32 == LBN_DBLCLK =>
            {
                confirm(window, lparam as HWND);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(window, message, wparam, lparam),
        }
    }
}

/// Records the highlighted row as the choice and closes the window, which ends the message loop.
/// Only posting the quit would leave the window on screen, unpumped and frozen, while the caller
/// reads.
unsafe fn confirm(window: HWND, listbox: HWND) {
    unsafe {
        let selected = SendMessageW(listbox, LB_GETCURSEL, 0, 0);
        let processes = PICK.with(|pick| pick.borrow().processes);
        if selected != LB_ERR as LRESULT && (selected as usize) < processes {
            PICK.with(|pick| pick.borrow_mut().chosen = Some(selected as usize));
            DestroyWindow(window);
        }
    }
}

fn loword(value: u32) -> i32 {
    (value & 0xffff) as i32
}

fn hiword(value: u32) -> i32 {
    ((value >> 16) & 0xffff) as i32
}

/// A NUL-terminated UTF-16 copy for the wide Win32 entry points.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(iter::once(0)).collect()
}
