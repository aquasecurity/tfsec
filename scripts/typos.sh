#!/bin/bash

highlight="\x1b[31m"
if [[ "$1" == "fix" ]]; then
    fix="-w"
    highlight="\x1b[32m"
fi

trim() {
    local var="$*"
    # remove leading whitespace characters
    var="${var#"${var%%[![:space:]]*}"}" 
    printf '%s' "$var"
}

which misspell || go install github.com/client9/misspell/cmd/misspell@latest
fixes=$(find . -type f | grep -v vendor/ | grep -v funcs/ | xargs misspell -error $fix)

[[ "$?" == "0" ]] && echo -e "\x1b[32mNo typos!\x1b[0m" && exit 0

count=$(echo "$fixes" | wc -l)

echo "$fixes" | while read fix; do
    file=$(echo $fix | awk -F':' '{print $1}')
    lineno=$(echo $fix | awk -F':' '{print $2}')
    column=$(echo $fix | awk -F':' '{print $3}')
    info=$(echo $fix | awk -F':' '{print $4}')
    line=$(sed "${lineno}q;d" $file)
    before=${line:0:$column}
    rest=${line:$column}
    typo=$(echo $rest | awk -F'[\(\[\]\)\":., ]' '{print $1}')
    endpos=$(echo "$before$typo" | wc -c)
    endpos=$(($endpos - 1))
    after=${line:$endpos}
    before=$(trim "$before")
    echo
    echo "$file:$lineno:$column"
    echo -e "\$highlight$info:\x1b[0m"
    echo -e " $before$highlight$typo\x1b[0m$after"
    echo
done

if [[ "$1" == "fix" ]]; then
    echo
    echo -e "\x1b[32mAll typos fixed!\x1b[0m"
    echo
else
    echo
    echo -e "\x1b[31mFound $count typo(s). Fix them all with 'make fix-typos'.\x1b[0m"
    echo
    exit 1
fi
