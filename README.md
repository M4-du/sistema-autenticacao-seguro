# Projeto Final — UC00606

Este projeto consiste numa plataforma de autenticação resiliente em modo consola, desenvolvida em Python, cujo objetivo é gerir utilizadores e acessos de forma segura, aplicando boas práticas de segurança informática.

Em sistemas de autenticação simples, é comum encontrar problemas como:

- armazenamento inseguro de passwords (em texto simples);
- ausência de registo de tentativas de login;
- vulnerabilidade a ataques de força bruta;
- inexistência de mecanismos de bloqueio de contas ou IPs;
- dificuldade em analisar padrões de acesso malicioso.

Este projeto foi criado para resolver esses problemas, simulando um sistema de autenticação mais robusto, semelhante aos utilizados em aplicações reais.

O sistema permite:

- a criação de utilizadores com passwords protegidas através de hash criptográfico;
- a realização de login com verificação de credenciais;
- o registo de todas as tentativas de acesso num ficheiro de logs;
- a deteção de comportamentos suspeitos, como múltiplas tentativas falhadas;
- a aplicação de bloqueios temporários de contas e bloqueio de IPs através de uma blacklist.
- O projeto está organizado em vários módulos, cada um com uma responsabilidade específica, promovendo uma estrutura clara, segura e fácil de manter.

## Ficheiros de dados incluídos

- `logs_exemplo.csv` — logs com 200+ tentativas de login (inclui padrões de ataque simulados)
- `users_secure.json` — utilizadores simulados com hash PBKDF2 + salt (sem passwords em claro)
- `blacklist.json` — começa vazio e é atualizado automaticamente pelo programa

## Utilizadores para testes

- admin / Admin!123
- madu / 1234Abcd!
- duda / Duda@2026
- guest / Guest#000

## IPs bloqueados para teste

198.51.100.77
203.0.113.55

## Comportamentos suspeitos e respetivas medidas de segurança

- ≥ 10 falhas do mesmo IP em 5 minutos → bloqueio temporário (1 hora)
- ≥ 30 falhas do mesmo IP em 24 horas → bloqueio permanente
- ≥ 5 utilizadores diferentes atacados pelo mesmo IP em 10 minutos → bloqueio temporário (1 hora)
- ≥ 3 falhas consecutivas numa conta → bloqueio temporário da conta com backoff exponencial

## Como testar rapidamente

1. Abre o terminal
2. Executa:
   - `python login_seguro_tk.py`
3. Escolhe as opções:

**1** para criar utilizador
**2** para fazer login
**3** para analisar logs e gerar a blacklist.
**0** para sair
