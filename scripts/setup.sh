cd ~
sudo apt-get update -y
sudo apt-get install -y tmux zsh tree htop cgdb gdb git tig gpg wget apt-transport-https
# oh-my-tmux
git clone https://github.com/gpakosz/.tmux.git
ln -s -f .tmux/.tmux.conf
cp .tmux/.tmux.conf.local .
echo "set -g history-limit 10000" >> ~/.tmux.conf.local
echo "set -g mouse on" >> ~/.tmux.conf.local
echo "set -gu prefix2" >> ~/.tmux.conf.local
echo "unbind C-t" >> ~/.tmux.conf.local
echo "unbind C-b" >> ~/.tmux.conf.local
echo "set -g prefix C-t" >> ~/.tmux.conf.local
echo "bind C-t send-prefix" >> ~/.tmux.conf.local
echo "bind c new-window -c '#{pane_current_path}'" >> ~/.tmux.conf.local
echo "set -g status-position top" >> ~/.tmux.conf.local

sudo wget https://raw.githubusercontent.com/brendangregg/FlameGraph/master/stackcollapse-perf.pl -O /usr/bin/stackcollapse-perf.pl
sudo wget https://github.com/brendangregg/FlameGraph/blob/master/flamegraph.pl -O /usr/bin/flamegraph.pl
sudo chmod +x /usr/bin/stackcollapse-perf.pl /usr/bin/flamegraph.pl

# install VScode
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" |sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null
rm -f packages.microsoft.gpg
apt-get update
apt-get install -y code

mkdir -p ~/workspace
cd ~/workspace
git clone https://github.com/microsoft/msquic
cd msquic
sh ./scripts/install-powershell.sh $1
pwsh ./scripts/prepare-machine.ps1
pwsh ./scripts/build.ps1

# oh-my-zsh
sh -c "$(wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"
