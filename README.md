# uwsgi protocol dissector

Experimental Wireshark dissector for the `uwsgi` protocol used by [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/).

## Install instructions for Wireshark on Windows

1. Go to `%APPDATA%\Wireshark` folder
2. Create `plugins` folder if it does not exist yet, and go there
3. Clone this repository there, or just copy the `uwsgi.lua` file there
4. If Wireshark is already running, use **Analyze - Reload Lua Plugins** (Ctrl-Shift-L)
5. Have fun with your capture file that contains uWSGI traffic
