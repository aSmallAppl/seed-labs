# 基于官方 SeedLab 镜像
FROM handsonsecurity/seed-ubuntu:large

# 更新源并预装 libpcap（你需要的依赖）
RUN apt-get update
RUN apt-get install -y gcc
RUN apt-get install -y libpcap0.8 libpcap-dev
RUN rm -rf /var/lib/apt/lists/*
