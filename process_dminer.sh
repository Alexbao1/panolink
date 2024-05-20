#!/bin/bash

# 输入文件
INPUT_FILE=$1

# 输出文件后缀
SUFFIX="_processed"
WARTS_SUFFIX=".warts"
# 使用输入文件名和后缀生成输出文件名
OUTPUT_FILE="${INPUT_FILE}${SUFFIX}"
WARTS_FILE="${OUTPUT_FILE}${WARTS_SUFFIX}"
# 使用tail和awk处理文件
# tail -n +2 跳过第一行
tail -n +2 "$INPUT_FILE" | awk -F, -v OFS=, '
{
    # 对第9列和第4列取第8位之后的字符串
    $9 = substr($9, 8);
    $4 = substr($4, 8);

    # 重新排列列的顺序，并输出
    print $9, $4, $11, $12, $1, $16, $7;
}' > "$OUTPUT_FILE"

echo "处理完成。输出文件: $OUTPUT_FILE"

sudo /root/anaconda3/bin/conda run -n yarrp /root/yarrp/utils/zmap2warts.py -i $OUTPUT_FILE -o $WARTS_FILE
