#Module Import
import platform, os, socket, requests, json, psutil

#Variable Assignment
Platform = platform.system()

#Function 1
def clear():
  if Platform == 'Linux':
    os.system("clear")

  elif Platform == 'Windows':
    os.system("cls")

#Function 2
OpenPorts = []
target = "127.0.0.1"
def port_scanner(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        print(f"{port}")
        OpenPorts.append(port)
    except:
        pass
    
#Function 3
def pushbullet_noti(title, body):
  TOKEN = 'o.pIEJHJ4pa8IheZa46OHXe0EwwwWgBrZB'
  # Make a dictionary that includes, title and body
  msg = {"type": "note", "title": title, "body": body}
  # Sent a posts request
  resp = requests.post('https://api.pushbullet.com/v2/pushes', data=json.dumps(msg),headers={'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'})
  if resp.status_code != 200:  # Check if fort message send with the help of status code
    raise Exception('Error', resp.status_code)
  else:
    print('Message sent')

#Function 4
def PortCloser(port):
    # find the process using the port
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conns in proc.connections(kind='inet'):
                if conns.laddr.port == port:
                    print(f"Process {proc.name()} (PID {proc.pid}) is using port {port}")
                    proc.terminate()
                    print('Process terminated')
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
