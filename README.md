# 装panolink环境

cd root/anaconda3/envs

git init

git remote add panolink_envs https://github.com/Alexbao1/panolink_envs.git

git pull panolink_envs master

# 装panolink本体

sudo apt install scamper docker.io

mkdir panolink

cd root/panolink

git init

git remote add panolink https://github.com/Alexbao1/panolink.git

git pull panolink master

把bdrmap、yarrp文件夹放root

chmod 777 ~/yarrp/utils/zmap2warts.py 

# 跑panolink

docker run --rm -d -p 8123:8123 clickhouse/clickhouse-server:22.6

docker ps, 改id

conda activate panolink

cd root/panolink

./run_panolink.sh
