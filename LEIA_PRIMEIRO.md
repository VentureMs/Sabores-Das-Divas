# Sabores das Divas — Sistema de gestão com acesso individual

## O que esta versão faz

Esta é uma **versão executável, preparada para implantação**, baseada no protótipo anterior. Contém **Clientes, Cardápio, Pedidos, Fechamento e extrato simplificado para WhatsApp**, agora com **login, usuários separados, permissões verificadas no servidor, histórico de alterações, SQLite centralizado e cópias de segurança**. Não é um link público já hospedado: para o acesso de qualquer lugar, ainda é necessário configurar um servidor e um endereço HTTPS.

Os **63 clientes** da última versão foram incluídos no arquivo `clientes_iniciais.json` (54 da Pedreira e 9 de Outros), com os **54 telefones disponíveis** no cadastro utilizado para a última versão. *Produtos, pedidos e pagamentos começam vazios em uma instalação nova.* Se você fez alterações no protótipo após ele ser entregue, use a opção de **exportar JSON na versão antiga** e a função de importação disponível em **Meus dados** no novo sistema **antes de registrar produtos ou pedidos online**. A importação substitui os clientes iniciais pelos clientes do seu backup anterior.

**O programa não deve ser aberto diretamente como um arquivo HTML.** Ele funciona por meio do `server.py`, que fornece páginas, login e banco de dados. Abrir `web/index.html` diretamente não conecta o banco e o login não funcionará.

## 1. Experimentar no próprio computador, sem hospedagem

Você precisa de **Python 3.11 ou superior**. O teste local não exige instalar bibliotecas Python nem contratar hospedagem.

**Windows:** extraia o ZIP completo para uma pasta privada e clique em `INICIAR_WINDOWS.bat`. No primeiro uso, siga as perguntas do terminal para criar nome, e-mail e senha do **administrador principal** (mínimo de 12 caracteres). **Nessa etapa inicial no CMD, a senha fica visível enquanto você a digita**, por solicitação da proprietária; verifique que ninguém possa ver sua tela. Se as duas senhas forem diferentes, o instalador pede uma nova senha e confirmação e **não cria a conta nem inicia o programa** até que coincidam. Nas outras telas e na implantação via servidor, a senha continua oculta. Os 63 clientes iniciais são incluídos somente quando a base está vazia. O navegador abrirá `http://127.0.0.1:8080`.

**macOS/Linux:** abra um terminal na pasta extraída e execute `sh INICIAR_MAC_LINUX.sh`; depois acesse `http://127.0.0.1:8080`.

**Atenção:** essa forma permite acesso **apenas no próprio computador**. Não abra a porta 8080 no roteador, não use HTTP pela internet e não copie a pasta `data/` para um servidor público. A janela/terminal deve permanecer aberto para que o sistema funcione. Se fechar, o banco continua gravado em `data/sabores.sqlite3`.

## 2. Criar contas com diferentes permissões

Após entrar como administrador, abra **Usuários → Convidar usuário**, informe nome, **nome de usuário**, e-mail e perfil. O sistema gera uma **senha provisória aleatória com exatamente 6 números**, exibida uma única vez. Entregue-a diretamente à pessoa autorizada por um canal privado; **o sistema não envia e-mails automaticamente**. A pessoa pode entrar usando **nome de usuário ou e-mail** e **não precisa trocar a senha provisória** para utilizar as funções permitidas ao seu perfil. Em **Minha conta → Alterar senha**, a troca é opcional; uma nova senha escolhida manualmente exige pelo menos 12 caracteres. Em **Usuários → Editar** você pode mudar nome de usuário, perfil ou desativar a conta; a alteração invalida as sessões existentes. Em **Nova senha** você pode emitir outro código provisório de 6 números, invalidando as sessões anteriores.

**Atenção à segurança:** um código de apenas seis números oferece proteção limitada, especialmente se mantido por longo prazo. Ative a autenticação em duas etapas (2FA) para todas as contas, especialmente administradores e financeiros; não reutilize o PIN, não o compartilhe em grupos e mantenha a restrição de tentativas de login e o HTTPS habilitados. A senha de **criação inicial do administrador no CMD** continua exigindo 12 ou mais caracteres.

**Excluir usuário:** em **Usuários → Excluir**, confirme digitando `EXCLUIR`. O sistema encerra suas sessões, bloqueia o login e retira a conta da lista de usuários. Os **pedidos, pagamentos e registros de auditoria não são apagados**: uma referência histórica inativa do usuário é mantida internamente para preservar a autoria. É possível reutilizar o nome de usuário e e-mail em um novo acesso, sem herdar os pedidos antigos. O administrador não pode excluir sua própria conta. Antes de substituir os arquivos, faça um backup da pasta `data/`.

| Função | Administrador | Operador | Financeiro |
| --- | --- | --- | --- |
| Consultar clientes e cardápio | Sim | Sim | Sim |
| Cadastrar/editar dados básicos de cliente | Sim | Sim | Não |
| Marcar inadimplência | Sim | Não | Não |
| Cadastrar/alterar preços do cardápio | Sim | Não | Não |
| Criar pedidos | Sim | Sim | Não |
| Consultar pedidos | Todos | Apenas os próprios | Todos |
| Editar pedidos | Sim, respeitando pagamentos já recebidos | Apenas os próprios, sem pagamentos | Não |
| Consultar fechamento, registrar pagamentos e quitar pedidos do mês em lote | Sim | Não | Sim |
| Gerenciar usuários, ver auditoria completa e exportar todos os dados | Sim | Não | Não |

Os bloqueios são verificados **no servidor**, inclusive quando alguém tenta enviar uma chamada direta à API. As senhas são armazenadas como hashes `scrypt`, nunca como texto legível. As sessões usam cookies `HttpOnly`, `SameSite=Strict` e, na hospedagem HTTPS, `Secure`. Recomendamos ativar **Minha conta → Ativar duas etapas** para o administrador e para usuários financeiros. O login pede um código de um aplicativo autenticador depois que o recurso é ativado.

O **Histórico** exibe os 250 eventos mais recentes e, em **Detalhes**, o conteúdo anterior/posterior quando registrado. O banco armazena os eventos, sem aplicar limite de 250 à tabela histórica.

## 3. Colocar online (servidor com Docker, domínio e HTTPS)

Esta etapa necessita de um **servidor Linux/VPS sob seu controle**, Docker com Compose instalado, domínio/subdomínio de sua titularidade e um registro DNS apontando para o IP público do servidor. Não foi realizada automaticamente por este pacote. Recomendamos revisão de segurança, atualizações do sistema operacional e configuração de firewall antes de guardar dados reais de clientes na internet.

1. Envie a pasta extraída ao servidor privado. Configure o DNS de `app.seudominio.com.br` para o IP do servidor.
2. Copie `.env.example` para `.env` e **substitua** `app.seudominio.com.br` pelo seu domínio real, sem `https://` e sem barra final. No firewall, exponha somente as portas **80 e 443** para a web; restrinja o acesso SSH. **Não exponha a porta 8080 da aplicação.**
3. Dentro da pasta no servidor, execute `docker compose up -d --build`. O contêiner `proxy` usa Caddy para obter/renovar certificados HTTPS; a aplicação só é acessível pelo proxy.
4. Configure o administrador (primeiro acesso) com `docker compose exec -it app python server.py bootstrap-admin`. Os dados cadastrados na instalação anterior no navegador ainda **não** são migrados automaticamente.
5. Se deseja começar com os 63 clientes iniciais e a base está vazia, execute `docker compose exec app python server.py seed-clients`. **Não faça isso se pretende importar um backup mais atualizado da versão antiga**: entre no sistema e importe o backup na aba **Meus dados** antes de criar pedidos ou produtos.
6. Visite `https://SEU_DOMÍNIO`, entre com o administrador e **ative a autenticação em duas etapas** em Minha conta. Crie contas de operadores/financeiros na aba Usuários.

`compose.yaml` mantém banco (`app_data`) e backups (`backup_data`) em volumes persistentes. `app` não publica a porta 8080; somente `proxy` publica 80/443. Uma mudança de servidor exige migrar tanto o volume do banco como as cópias de segurança ou restaurar um backup previamente testado.

### Importante: não é um serviço já contratado e em execução

Este pacote **não inclui** domínio, VPS, assinatura de hospedagem, contas de e-mail para entrega de convites nem sincronização com o antigo arquivo HTML de forma automática. Se alguém abrir o link do arquivo HTML da versão anterior, continuará usando o **protótipo antigo no navegador**, e não a base online. Oriente as pessoas autorizadas a usar exclusivamente o novo endereço HTTPS.

## 4. Como funcionam os backups

Na implantação com Docker, o serviço `backup` faz uma cópia consistente do SQLite na inicialização e aproximadamente a **cada 24 horas**, verifica a integridade e remove os backups locais com **mais de 30 dias**. Esses backups são gravados no volume `backup_data`, no **mesmo servidor**. Uma falha, roubo ou exclusão do servidor pode afetar o banco **e** esse volume.

**Obrigatório complementar:** programe a cópia periódica dos backups para armazenamento **privado e independente** (por exemplo, um espaço de armazenamento em nuvem com controle de acesso, criptografia e retenção/versionamento), de preferência diariamente. Restrinja a leitura dos backups: o SQLite inclui nomes, telefones, observações, pedidos, pagamentos e hashes de senha. Não envie arquivos de backup para grupos de WhatsApp, links públicos ou armazenamento sem proteção. Teste a restauração antes de depender desse sistema para vendas reais.

Backup manual durante o teste local: feche o servidor, abra um terminal na pasta do projeto e execute `python server.py backup` (Windows) ou `python3 server.py backup` (macOS/Linux). O arquivo aparecerá na pasta `backups/`; copie-o para um local seguro separado do computador.

**Restauração:** mantenha o app parado; guarde uma cópia do banco atual; escolha um backup íntegro; copie-o para o arquivo `data/sabores.sqlite3` **somente com o servidor e o serviço de backup parados** e remova os antigos arquivos auxiliares `sabores.sqlite3-wal` e `sabores.sqlite3-shm` antes de reiniciar. Em Docker, faça a restauração dentro do volume `app_data` por um administrador do servidor. A restauração volta usuários, pedidos e pagamentos para o estado da data do backup; confira o período antes de sobrescrever a base.

### Acesso excepcional se perder o autenticador do administrador

Somente alguém com acesso ao terminal do **servidor** poderá executar `python server.py recover-admin` (teste local) ou `docker compose exec -it app python server.py recover-admin` (Docker). A recuperação redefine senha, desativa o segundo fator da conta indicada, revoga suas sessões e registra um evento no histórico. Depois, ative novamente duas etapas.

## 5. Testes e limitações

O pacote inclui testes de API para login com usuário/e-mail, PIN de 6 dígitos sem troca obrigatória, exclusão de usuário com preservação de pedidos/pagamentos, autorização por perfil, pedidos, preço histórico, pagamento em lote, bloqueio de duplicação de pagamento, 2FA, auditoria e integridade do backup: `python -m unittest discover -s tests -v`.

**Este software é uma implementação inicial**, não uma certificação de segurança: antes da exposição pública com informações reais, revise a infraestrutura e o código, confirme a política de cópia externa e faça testes dos fluxos de trabalho em seus aparelhos. Não armazene documentos bancários ou senhas dos clientes em observações. O acesso HTTPS protege a transmissão; a proteção do disco/backup do servidor deve ser configurada pelo responsável pela hospedagem.
