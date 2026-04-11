# 基于官方 SeedLab 镜像
FROM handsonsecurity/seed-ubuntu:large

# 更新源并预装 libpcap（你需要的依赖）
RUN apt-get update && \
    apt-get install -y gcc && \
    apt-get install -y libpcap0.8 libpcap-dev && \
    rm -rf /var/lib/apt/lists/*
