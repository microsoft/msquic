sudo apt-get update -y
sudo apt-get install tmux zsh tree htop cgdb gdb git tig
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

mkdir -p ~/workspace
cd ~/workspace
git clone https://github.com/microsoft/msquic
cd msquic
sh ./scripts/install-powershell.sh $1
pwsh ./scripts/prepare-machine.ps1
pwsh ./scripts/build.ps1

# oh-my-zsh
sh -c "$(wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"
