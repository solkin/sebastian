#!/bin/sh
# Lists stored objects that may still hold S3 aws-chunked framing instead of
# their content.
#
# Sebastian v1.6.0 and earlier acknowledged some streaming S3 uploads
# (Content-Encoding: aws-chunked) while storing the chunk framing and trailer
# rather than the decoded bytes; v1.6.1 fixed new uploads but cannot repair
# stored objects.
# Such a file starts with a hexadecimal chunk size followed by
# ";chunk-signature=" or by CRLF, and usually ends with a zero-length chunk and
# trailing headers such as "x-amz-checksum-crc32:".
#
# Usage: find-aws-chunked [ROOT_DIR]      (default /data/files)
#   docker exec sebastian find-aws-chunked
#
# Every listed file must be compared with its original checksum and uploaded
# again if it differs. A text file that happens to start with a hex number and
# CRLF can be listed too; the check is deliberately inclusive.
set -eu

root=${1:-/data/files}
[ -d "$root" ] || { echo "not a directory: $root" >&2; exit 2; }

found=0
find "$root" -path "$root/.sebastian" -prune -o -type f ! -name '.seb-*' -print |
while IFS= read -r file; do
	head=$(head -c 96 "$file" 2>/dev/null | tr -d '\000') || continue
	case $head in
	[0-9a-fA-F]*\;chunk-signature=*) echo "$file" ;;
	*)
		first=$(printf '%s' "$head" | head -n 1)
		case $first in
		*[!0-9a-fA-F$(printf '\r')]* | "") ;;
		*)
			if tail -c 512 "$file" 2>/dev/null | grep -aqiE '^(0|x-amz-checksum-[a-z0-9]+:|x-amz-trailer-signature:)'; then
				echo "$file"
			fi
			;;
		esac
		;;
	esac
done
