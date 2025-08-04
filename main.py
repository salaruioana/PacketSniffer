from gui import PacketSnifferGUI
import tkinter as tk

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

