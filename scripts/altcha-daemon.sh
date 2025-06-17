#!/bin/sh

# ALTCHA Server Daemon Script
# Usage: altcha-daemon.sh {start|stop|restart|status}

DAEMON_NAME="altcha-server"
DAEMON_PATH="/usr/local/bin/altcha-server"
PID_FILE="/var/run/altcha-server.pid"
LOG_FILE="/var/log/altcha-server.log"
DAEMON_USER="www"

# Check if daemon exists
if [ ! -x "$DAEMON_PATH" ]; then
    echo "Error: $DAEMON_PATH not found or not executable"
    exit 1
fi

# Function to get PID
get_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE"
    fi
}

# Function to check if process is running
is_running() {
    pid=$(get_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to start the daemon
start_daemon() {
    if is_running; then
        echo "ALTCHA server is already running (PID: $(get_pid))"
        return 1
    fi

    echo "Starting ALTCHA server..."
    
    # Ensure log file exists and has correct permissions
    touch "$LOG_FILE"
    chown "$DAEMON_USER:$DAEMON_USER" "$LOG_FILE"
    
    # Start the daemon
    su -s /bin/sh "$DAEMON_USER" -c "nohup $DAEMON_PATH >> $LOG_FILE 2>&1 & echo \$!" > "$PID_FILE"
    
    # Wait a moment and check if it started successfully
    sleep 2
    if is_running; then
        echo "ALTCHA server started with PID $(get_pid)"
        return 0
    else
        echo "Failed to start ALTCHA server"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Function to stop the daemon
stop_daemon() {
    if ! is_running; then
        echo "ALTCHA server is not running"
        rm -f "$PID_FILE"
        return 1
    fi

    echo "Stopping ALTCHA server (PID: $(get_pid))..."
    
    pid=$(get_pid)
    kill "$pid"
    
    # Wait for process to stop
    for i in $(seq 1 10); do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    
    # Force kill if still running
    if kill -0 "$pid" 2>/dev/null; then
        echo "Process still running, force killing..."
        kill -9 "$pid"
        sleep 1
    fi
    
    rm -f "$PID_FILE"
    echo "ALTCHA server stopped"
    return 0
}

# Function to restart the daemon
restart_daemon() {
    stop_daemon
    sleep 2
    start_daemon
}

# Function to show status
show_status() {
    if is_running; then
        echo "ALTCHA server is running (PID: $(get_pid))"
        return 0
    else
        echo "ALTCHA server is not running"
        return 1
    fi
}

# Main script logic
case "$1" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        restart_daemon
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit $?
