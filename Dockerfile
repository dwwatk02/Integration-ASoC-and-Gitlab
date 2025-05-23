FROM ubuntu:latest
ENV HOME="/root/"
ENV PATH="$HOME/SAClientUtil/bin:${PATH}"
RUN apt update
RUN apt install -y curl unzip maven openjdk-11-jre gradle && apt clean
RUN curl https://cloud.appscan.com/api/v4/Tools/SAClientUtil?os=linux > $HOME/SAClientUtil.zip
RUN unzip $HOME/SAClientUtil.zip -d $HOME
RUN rm -f $HOME/SAClientUtil.zip
RUN mv $HOME/SAClientUtil.* $HOME/SAClientUtil
