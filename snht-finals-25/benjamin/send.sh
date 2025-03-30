#!/bin/bash

# Check if a string is provided as input
# if [ "$#" -ne 1 ]; then
#   echo "Usage: $0 \"your_text_data\""
#   exit 1
# fi

TEXT_DATA="$1"

# Define the cURL command
curl 'https://bencode.finals.snht.se:1337/' \
  -H 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryExample' \
  --data-raw $'------WebKitFormBoundaryExample\r\nContent-Disposition: form-data; name="action"\r\n\r\n/\r\n------WebKitFormBoundaryExample\r\nContent-Disposition: form-data; name="torrentFile"; filename="input.torrent"\r\nContent-Type: application/x-bittorrent\r\n\r\n'"$TEXT_DATA"$'\r\n------WebKitFormBoundaryExample--\r\n' \
  --insecure

