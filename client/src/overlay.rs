//! A topmost, click-through window that draws the projected figure over the game.
//!
//! The window is one colour-keyed layer: everything painted in [`KEY`] is a hole, so only the pen
//! shows. It never takes focus (`WS_EX_NOACTIVATE`) and never appears in the taskbar
//! (`WS_EX_TOOLWINDOW`), and it draws only the lines it is handed — the window procedure reads no
//! memory, so a slow read never stalls the window's own messages.
//!
//! A layered window does not composite over an exclusive-fullscreen game; run the game in borderless
//! or windowed mode. The window covers the screen rectangle it is opened with, from the top-left of
//! the primary monitor, so the pixels it draws are game pixels when the game fills that rectangle.

use std::{cell::RefCell, mem, ptr};

use windows_sys::Win32::{
    Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::Gdi::{
        BeginPaint, CreatePen, CreateSolidBrush, DeleteObject, EndPaint, FillRect, HBRUSH, HPEN,
        InvalidateRect, LineTo, MoveToEx, PAINTSTRUCT, PS_SOLID, SelectObject, UpdateWindow,
    },
    System::LibraryLoader::GetModuleHandleW,
    UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, IsWindow,
        LWA_COLORKEY, MSG, PM_REMOVE, PeekMessageW, PostQuitMessage, RegisterClassW,
        SW_SHOWNOACTIVATE, SetLayeredWindowAttributes, ShowWindow, TranslateMessage,
        UnregisterClassW, WM_DESTROY, WM_ERASEBKGND, WM_PAINT, WM_QUIT, WNDCLASSW, WS_EX_LAYERED,
        WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
    },
};

/// The window class, apart from the picker's own.
const CLASS: &str = "SvmVisorOverlay";

/// The colour a hole is painted in: a magenta no game draws.
const KEY: COLORREF = 0x00ff_00ff;

/// The pen every line is drawn with: green in `COLORREF`'s `0x00bbggrr` order.
const LINE_COLOR: COLORREF = 0x0000_ff00;
const LINE_WIDTH: i32 = 1;

thread_local! {
    /// What the window procedure paints. The GDI objects live here so the procedure, which has no
    /// state of its own, can reach them without a shared owner.
    static PAINTER: RefCell<Option<Painter>> = const { RefCell::new(None) };
}

/// One overlay window, and the class name it was made from.
pub struct Overlay {
    window: HWND,
    class: Vec<u16>,
}

impl Overlay {
    /// Opens a click-through window over `width` x `height` pixels of the primary monitor, `None`
    /// when Windows refuses the window.
    pub fn open(width: u32, height: u32) -> Option<Self> {
        // SAFETY: every handle is checked, the class is unregistered by `Drop`, and the whole
        // overlay lives on the thread that opened it, with the window procedure.
        unsafe { create(width, height) }
    }

    /// Replaces what the window paints and repaints it at once.
    pub fn draw(&mut self, lines: &[((f32, f32), (f32, f32))]) {
        PAINTER.with(|painter| {
            if let Some(painter) = painter.borrow_mut().as_mut() {
                painter.lines.clear();
                painter.lines.extend_from_slice(lines);
            }
        });
        // SAFETY: the window belongs to this thread and lives until this value is dropped.
        unsafe {
            InvalidateRect(self.window, ptr::null(), 0);
            UpdateWindow(self.window);
        }
    }

    /// Handles the window's messages and says whether it is still open.
    pub fn pump(&mut self) -> bool {
        let mut message: MSG = unsafe { mem::zeroed() };
        // SAFETY: `message` is a live, correctly typed message and the queue belongs to this thread.
        while unsafe { PeekMessageW(&mut message, ptr::null_mut(), 0, 0, PM_REMOVE) } > 0 {
            if message.message == WM_QUIT {
                return false;
            }
            // SAFETY: the message came from this thread's own queue.
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        // Closing by any other means, such as the desktop's own window management, ends it too.
        unsafe { IsWindow(self.window) != 0 }
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        // SAFETY: the objects were created by this thread and no paint is in progress, so nothing
        // has them selected into a device context.
        unsafe {
            PAINTER.with(|painter| {
                if let Some(painter) = painter.borrow_mut().take() {
                    DeleteObject(painter.pen);
                    DeleteObject(painter.background);
                }
            });
            DestroyWindow(self.window);
            UnregisterClassW(self.class.as_ptr(), GetModuleHandleW(ptr::null()).cast());
        }
    }
}

/// The lines one overlay paints, and the GDI objects it paints them with.
struct Painter {
    lines: Vec<((f32, f32), (f32, f32))>,
    pen: HPEN,
    background: HBRUSH,
}

impl Painter {
    /// The pen and the background brush the key colour is painted with.
    fn new() -> Self {
        // SAFETY: creating GDI objects takes no other precondition; `Drop` deletes them.
        unsafe {
            Self {
                lines: Vec::new(),
                pen: CreatePen(PS_SOLID, LINE_WIDTH, LINE_COLOR),
                background: CreateSolidBrush(KEY),
            }
        }
    }
}

/// Creates the window and installs the painter.
unsafe fn create(width: u32, height: u32) -> Option<Overlay> {
    unsafe {
        let instance = GetModuleHandleW(ptr::null());
        let class = wide(CLASS);
        let window_class = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(procedure),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance.cast(),
            hIcon: ptr::null_mut(),
            hCursor: ptr::null_mut(),
            // The window paints every pixel of itself, so it wants no background brush.
            hbrBackground: ptr::null_mut(),
            lpszMenuName: ptr::null(),
            lpszClassName: class.as_ptr(),
        };
        if RegisterClassW(&window_class) == 0 {
            return None;
        }
        let extended =
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE;
        let window = CreateWindowExW(
            extended,
            class.as_ptr(),
            ptr::null(),
            WS_POPUP,
            0,
            0,
            width as i32,
            height as i32,
            ptr::null_mut(),
            ptr::null_mut(),
            instance.cast(),
            ptr::null(),
        );
        if window.is_null() {
            UnregisterClassW(class.as_ptr(), instance.cast());
            return None;
        }
        SetLayeredWindowAttributes(window, KEY, 0, LWA_COLORKEY);
        PAINTER.with(|painter| *painter.borrow_mut() = Some(Painter::new()));
        ShowWindow(window, SW_SHOWNOACTIVATE);
        Some(Overlay { window, class })
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
            // Every paint fills the window, so the default erase would only flicker.
            WM_ERASEBKGND => 1,
            WM_PAINT => {
                paint(window);
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

/// Fills the window with the key colour, then draws the current frame over it.
unsafe fn paint(window: HWND) {
    unsafe {
        let mut state: PAINTSTRUCT = mem::zeroed();
        let device = BeginPaint(window, &mut state);
        PAINTER.with(|painter| {
            let mut painter = painter.borrow_mut();
            let Some(painter) = painter.as_mut() else { return };
            let mut client: RECT = mem::zeroed();
            GetClientRect(window, &mut client);
            FillRect(device, &client, painter.background);
            let pen = SelectObject(device, painter.pen);
            for &((from_x, from_y), (to_x, to_y)) in &painter.lines {
                MoveToEx(device, from_x as i32, from_y as i32, ptr::null_mut());
                LineTo(device, to_x as i32, to_y as i32);
            }
            SelectObject(device, pen);
        });
        EndPaint(window, &state);
    }
}

/// A NUL-terminated UTF-16 copy for the wide Win32 entry points.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
