# Path to the input pcap file
$InputFile = "C:\Users\Itamar\Desktop\hello\qqq.pcap"

# Path to tshark
$tshark = "C:\Program Files\Wireshark\tshark.exe"

# Output folder
$OutputFolder = "C:\Users\Itamar\Desktop\hello\split_streams\"
if (!(Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder
}

# Extract unique HTTP/2 stream IDs
$StreamIDs = & $tshark -r $InputFile -o tls.keylog_file:$KeyLogFile -Y "http2" -T fields -e http2.streamid | Sort-Object -Unique

# Extract packets for each stream
foreach ($StreamID in $StreamIDs) {
    $OutputFile = "$OutputFolder\http2stream$StreamID.pcap"
    Write-Host "Extracting stream ID $StreamID to $OutputFile"
    & $tshark -r $InputFile -Y "http2.streamid == $StreamID" -w $OutputFile
}
