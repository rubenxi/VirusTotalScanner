#!/usr/bin/env bash

api_keys=(
  "[API_KEY 1]"
  "[API_KEY 2]"
)
api_key="${api_keys[0]}"

report_file="/tmp/VirusTotalScannerLastReport.txt"
malicious_files=()
really_malicious_files=()

skip=false

# Argument parsing
for arg in "$@"; do
  case $arg in
    --skip-upload)
      skip=true
      shift
      ;;
    --noskip)
      skip=false
      shift
      ;;
    *)
      echo "Unknown option: $arg"
      ;;
  esac
done

iterate_api() {
  local i
  for i in "${!api_keys[@]}"; do
    if [[ "${api_keys[i]}" == "$api_key" ]]; then
      break
    fi
  done

  ((i = (i + 1) % ${#api_keys[@]}))
  sleep 2
  api_key="${api_keys[i]}"
  echo "🔁 Quota exceeded, trying API key $i" >&2
}

analyze_hash() {
  hash=$(sha256sum "$1" | awk '{print $1}')
  json=''

  while true; do
    json=$(curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/files/$hash" \
      --header "accept: application/json" \
      --header "x-apikey: $api_key")

    if echo "$json" | jq -e '.error.code == "QuotaExceededError"' >/dev/null; then
      iterate_api
    else
      break
    fi
  done

  echo "$json"
}

analyze() {
  uploading="no"

  while true; do
    json="$(analyze_hash "$1")"

    if echo "$json" | jq -e '
      .error.code == "NotFoundError" or
      .error.message == "Resource not found."
    ' >/dev/null; then
        if $skip
        then
            echo "⏭️ Skipping analysis for $1"
            return
        fi
      if [[ "$uploading" == "no" ]]; then
        echo "📁 File hash not in database. Uploading file..."
        uploading="yes"
        analyze_file "$1"
        sleep 10
      else
        echo "📁 Analyzing..." >&2
        sleep 10
      fi
    else
      json_correct=$(echo "$json" | jq -e '
        .data.attributes.last_analysis_results
        | to_entries[]
        | has("value") and (.value | has("category"))
      ' >/dev/null 2>&1 && echo "yes" || echo "no")

      if [[ "$json_correct" == "yes" ]]; then
        break
      fi
    fi
  done

  analyze_json "$json" "$1"
}

analyze_json() {
  json="$1"
  file="$2"

  detections=$(echo "$json" | jq -r '
    .data.attributes.last_analysis_results
    | to_entries[]
    | select(.value.category | ascii_downcase == "malicious")
    | "\(.key)\t\(.value.category)"
  ')

  json_correct=$(echo "$json" | jq -e '
    .data.attributes.last_analysis_results
    | to_entries[]
    | has("value") and (.value | has("category"))
  ' >/dev/null 2>&1 && echo "yes" || echo "no")

  if [[ "$json_correct" == "yes" ]]; then
    if [[ -z "$detections" ]]; then
      count=0
    else
      count=$(echo "$detections" | grep -c . || echo 0)
    fi

    if [[ $count -gt 0 ]]; then
      malicious_files+=("$file")
      echo -e "\e[38;5;208m❗Detected malware for the file:
[$file]\e[0m
-----------------------
Detections: $count" | tee -a "$report_file"

      if [[ $count -gt 5 ]]; then
        echo -e "\e[31m
###################
⚠️ MORE THAN 5 PROVIDERS FOUND MALWARE FOR THIS FILE. IT'S PROBABLY NOT A FALSE POSITIVE ⚠️
###################\e[0m" | tee -a "$report_file"

        notify-send -u critical -a "VirusTotalScanner" -i dialog-information \
          "⚠️Malicious file found⚠️" "Found a malicious file while scanning.
Probably not a false positive."

        really_malicious_files+=("$file")
      fi

      echo "-----------------------" | tee -a "$report_file"
      echo "$detections" | while IFS=$'\t' read -r av category; do
        echo -e "$av | $category" | tee -a "$report_file"
      done
    else
      echo -e "\e[32m✅ Clean: $file\e[0m"
    fi

    echo "########################"
  else
    echo -e "\e[31mERROR GETTING JSON FILE FROM API: $file\e[0m"
  fi
}

analyze_file() {
  file="$1"
  json=''

  while true; do
    json=$(curl -s --request POST \
      --url https://www.virustotal.com/api/v3/files \
      --header 'accept: application/json' \
      --header 'content-type: multipart/form-data' \
      --header "x-apikey: $api_key" \
      --form file=@"$file")

    if echo "$json" | jq -e '.error.code == "QuotaExceededError"' >/dev/null; then
      iterate_api
    else
      break
    fi
  done
}

# Select directory
dir=$(zenity --file-selection --directory --title="Select a folder to scan" 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$dir" ]; then
  read -e -p "Enter folder path to search: " dir
fi

dir="${dir/#\~/$HOME}"

if [[ -z "$dir" ]]; then
  echo "No directory provided. Exiting." >&2
  exit 2
fi

if [[ ! -d "$dir" ]]; then
  echo "Directory does not exist: $dir" >&2
  exit 3
fi

echo "Starting analysis for .exe and .dll files in: $dir"
echo "#################"
echo "" >"$report_file"

found_any=false
while IFS= read -r -d '' file; do
  analyze "$file"
  found_any=true
done < <(find "$dir" -type f \( -iname '*.exe' -o -iname '*.dll' -o -iname '*.msi' \) -print0 2>/dev/null)

if [[ $found_any == false ]]; then
  echo "No .exe or .dll files found under: $dir"
fi

echo "#################
List of malicious files found:
" | tee -a "$report_file"

for item in "${malicious_files[@]}"; do
  echo -e "\e[38;5;208m$item\e[0m" | tee -a "$report_file"
done

echo "#################
LIST OF MALICIOUS FILES WITH MANY REPORTS:
" | tee -a "$report_file"

for item in "${really_malicious_files[@]}"; do
  echo -e "\e[31m$item\e[0m" | tee -a "$report_file"
done
echo "#################"
echo "Saved report to: $report_file"
