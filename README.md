# Desafio SSH reverso 

Passos do Levantamento:

1. Instalação e configuração :
    1. Instalação:
        1. instalar o cliente :
            - `sudo apt-get install openssh-server`
        2. instalar o servidor :
            - `sudo apt-get install openssh-client`
    2. conectar a partir do cliente :
        1. ssh usuario IP@nome_host
            - ssh ray@192.168.2.47
        2. Em nosso exemplo em execução, o usuário”ray” é autenticado pelo servidor SSH via senha de login.
- Para que uma senha seja segura, ela deve ser longa e aleatória, mas senhas são difíceis de memorizar.
- Uma senha enviada pela rede, mesmo protegida por um canal seguro SSH, pode ser capturada ao chegar ao host remoto se esse host tiver sido comprometido.
- A maioria dos sistemas operacionais suporta apenas uma única senha por conta. Para contas compartilhadas (por exemplo, uma conta de superusuário), isso apresenta dificuldades:
    - As alterações de senha são inconvenientes porque a nova senha deve ser comunicado a todas as pessoas com acesso à conta.
    - O rastreamento do uso da conta torna-se difícil porque o sistema operacional não faz distinção entre os diferentes usuários da conta.

Obs: Para resolver esses problemas, o SSH oferece suporte à autenticação de chave pública: em vez de depender do esquema de senha do sistema operacional do host, o SSH pode usar chaves gráficas criptográficas. As chaves são mais seguras do que as senhas em geral e tratam de todos os pontos fracos mencionados anteriormente.

2. Autenticação por Chave Criptográfica:

Para usar a autenticação criptográfica, você deve primeiro gerar um par de chaves para si mesmo, consistindo de uma chave privada (sua identidade digital que fica na máquina cliente) e uma chave pública (que fica na máquina servidora). Para fazer isso, use o  ssh-keygen para produzir uma chave DSA ou RSA. A versão OpenSSH do ssh-keygen requer que você especifique o tipo de chave com a opção --t (não há padrão):

- DSA :
    - Só funciona com SSH2
    - Velocidade de verificação mais rápida mas em comparação ao RSA (mas não é discrepante)
- RSA :
    - O RSA funciona com SSH2 e SSH (considerado altamente falho)
    - chaves maiores requerem mais tempo para serem geradas

```
cd ~/.ssh
ssh-keygen -t dsa
```

Generating public/private dsa key pair.Enter file in which to save the key (/home/servidor/.ssh/id_dsa): < aperte enter > Enter passphrase (empty for no passphrase): < Digite uma palavra chave > 4321Enter same passphrase again: < Redigite uma palavra chave > 4321Your identification has been saved in 1234Your public key has been saved in 1234.pubThe key fingerprint is:SHA256:ReEa7F4Vn+Mpdso+F/B/Ro7JmzZ0aAypzWX6Wl8px4A servidor@servidor-vastroThe key's randomart image is:+---[DSA 1024]----+|          o..    ||       . o   o . ||        o o ..+  ||       . + .=.oo ||        S .EoX+. ||       . ..o++X +||        .   o*.%.||           ...@o*||            o=o+o|+----[SHA256]-----+➜  .ssh pwd/home/servidor/.ssh➜  .ssh  ls -ltotal 16-rw------- 1 servidor servidor 1434 jun 30 13:34 1234-rw-r--r-- 1 servidor servidor  614 jun 30 13:34 1234.pub-rw-r--r-- 1 servidor servidor 2442 jun 28 18:42 known_hosts-rw-r--r-- 1 servidor servidor 2442 jun 28 13:46 known_hosts.old

Mova a chave pública para a maquina (servidor) de destino :

```
scp id_rsa.pub <user>@<yourhost>:.ssh/authorized_keys
```

```
cd ~/.ssh
ssh-keygen -t rsa
```

Generating public/private dsa key pair.Enter file in which to save the key (/home/servidor/.ssh/id_dsa): < aperte enter > Enter passphrase (empty for no passphrase): < aperte enter >Enter same passphrase again: < aperte enter > Your identification has been saved in rsaYour public key has been saved in rsa.pubThe key fingerprint is:SHA256:ReEa7F4Vn+Mpdso+F/B/Ro7JmzZ0aAypzWX6Wl8px4A servidor@servidor-vastroThe key's randomart image is:+---[DSA 1024]----+|          o..    ||       . o   o . ||        o o ..+  ||       . + .=.oo ||        S .EoX+. ||       . ..o++X +||        .   o*.%.||           ...@o*||            o=o+o|+----[SHA256]-----+➜  .ssh pwd/home/servidor/.ssh➜  .ssh  ls -ltotal 16-rw------- 1 servidor servidor 1434 jun 30 13:34 rsa-rw-r--r-- 1 servidor servidor  614 jun 30 13:34 rsa.pub-rw-r--r-- 1 servidor servidor 2442 jun 28 18:42 known_hosts-rw-r--r-- 1 servidor servidor 2442 jun 28 13:46 known_hosts.old

Mova a chave pública para a maquina (servidor) de destino :

```
scp 1234.pub <user>@<yourhost>:.ssh/authorized_keys
```

1. configuração OpenSSH :
    1. Configurando o OpenSSH no seu servidor:

Por padrão, o OpenSSH está apenas ouvindo127.0.0.1, portanto não poderemos acessar nossas portas encaminhadas de fora. Para que ele escute na interface conectada à Internet, precisamos habilitar aGatewayPortsopção na configuração do servidor SSH.

Abra/etc/ssh/sshd_configusando o seu editor de texto favorito.

```
  nano /etc/ssh/sshd_config
```

```
GatewayPorts yes
PubkeyAuthentication yes
```

```
service ssh restart
```

### tunelamento:

Se o seu computador doméstico executar o Linux, você precisará usar osshcomando da seguinte maneira:

```
ssh -R [Port to forward]:localhost:[Port to forward on your local machine] [user@IP]

```

Neste exemplo, estamos encaminhando a porta19132aberta em sua máquina doméstica para a porta80em seu servidor remoto (supondo que o endereço IP do servidor seja 192.168.0.1).

```
ssh -R 80:localhost:19132 user@192.168.0.1

```

Isso permitirá que você acesse sua máquina doméstica a partir de um local remoto, conectando-se a192.168.0.1:80

1. Comunicação entre Raspberry e Computador com túnel reverso.
    1. No Raspberry digite :
        - ssh -R 8081:localhost:22 servidor@172.20.10.2
    2. No servidor digite :
        - ssh ray@localhost -p 8081
2. Comunicação entre Raspberry e Computador com tunel reverso através da porta 80.
3. Comunicação entre PC Ray e PC do Júlio através de túnel reverso.
4. Comunicação entre: Raspberry <> Servidor Remoto <> PC Ray.
    1. No Raspberry digite :
        - sudo ssh -i ray-julio.pem -N -R 0.0.0.0:7071:localhost:22 ubuntu@ec2-44-192-129-106.compute-1.amazonaws.com
            - Aqui usamos o sinalizador -R para especificar o ponto de entrada remoto. A sintaxe exata de usar isso é -R [bind_address:]port:host:hostport . No nosso caso, isso seria localhost:7070:localhost:22. O primeiro localhost é o endereço na máquina remota onde o ponto de entrada remoto deve estar. Nós ignoramos isso no exemplo porque é por padrão localhost. A porta 7070 é a porta TCP na máquina remota que escutará conexões SSH com a máquina local. O próximo localhost refere-se à máquina local a partir da qual o túnel é criado. A porta 22 no final é a porta local (porta SSH padrão) para a qual as conexões serão encaminhadas da porta 7070 no host remoto.
    2. No PC do Ray digite :
        - ssh ray@ec2-44-192-129-106.compute-1.amazonaws.com -p 7071
    3. No servidor da AWS digite :
        1. Para abrir o código de configuração do ssh do servidor digite :
            - sudo nano /etc/ssh/sshd_config
        2. Altere as configurações das nomeclaturas abaixo para yes : AllowAgentForwarding yesAllowTcpForwarding yesGatewayPorts yes
5. sudo ssh -i ray-julio.pem -N -R 7070:localhost:22 [ubuntu@ec2-44-192-129-106.compute-1.amazonaws.com](mailto:ubuntu@ec2-44-192-129-106.compute-1.amazonaws.com)

https://gist.github.com/sandeeprenjith/0a9ab7edb86e390eb8ce1f6a59ce8c56

5. Script para configuração ssh com túnel reverso e api para alocação de porta no servidor.

[script](https://charlesreid1.com/wiki/RaspberryPi/Reverse_SSH)

5.1 Script para criar o túnel persistente:

- Crie um arquivo no Raspberry chamado ~/create_ssh_tunnel.sh e coloque isso nele:
    
    ```
    #!/bin/bash
    createTunnel() {
      /usr/bin/ssh -N -R 2222:localhost:22 serverUser@25.25.25.25
      if [[ $? -eq 0 ]]; then
        echo Tunnel to AWS created successfully
      else
        echo An error occurred creating a tunnel to AWS. RC was $?
      fi
    }
    /bin/pidof ssh
    if [[ $? -ne 0 ]]; then
      echo Creating new tunnel connection
      createTunnel
    fi
    ```
    

O que este programa está fazendo é verificar se há um processo em execução chamado 'ssh'. Se não houver, inicie o túnel ssh.

- Torne-o executável fazendo o seguinte:
    
    ```
    chmod 700 ~/create_ssh_tunnel.sh
    ```
    
- Agora inicie o crontab :
    
    ```
    crontab -e
    ```
    
- Crie uma tarefa em seu cron job (a cada minuto verifique se a conexão ssh está ativa, caso contrário, tente ativá-la)
    
    ```
      */1 * * * * ~/create_ssh_tunnel.sh > tunnel.log 2>&1
    ```
    

Quando o Raspberri Pi está ligado, ele verifica a cada minuto se existe uma conexão ssh com seu servidor ubuntu. Se isso não acontecer, ele criará um. O túnel que ele cria é realmente um túnel remoto reverso. Assim que o túnel estiver ativo, qualquer pessoa que fizer ssh na porta 2222 do servidor linux será redirecionada para o Pi. Incrível!
