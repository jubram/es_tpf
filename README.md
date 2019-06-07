# Engenharia de Segurança

## Vulnerabilities Mapping

Raphael Jubram Sawaia Pinheiro (pg37160@alunos.uminho.pt)

#### Gestão de Vulnerabilidades

Uma das principais atividades de equipes de Segurança da Informação é fazer a Gestão de Vulnerabilidades. Nesse trabalho, os analistas de segurança precisam identificar vulnerabilidades nos sistemas e tecnologias utilizados pela empresa e definir um plano de correção, com o objetivo de minimizar os riscos de ataques cibernéticos.

As vulnerabilidades podem ser identificadas de diversas formas, das quais, as mais comuns são:

- Varreduras de Vulnerabilidades;
- Testes de Intrusão (penetration tests);
- Programas de Bug Bounty;
- Contribuição de usuários;
- Pesquisas internas.

##### Ferramentas de Varredura

As varreduras de vulnerabilidades fazem parte do processo contínuo de gestão de vulnerabilidades para empresas preocupadas com sua segurança cibernética. Existem diversas ferramentas especializadas em realizar esse tipo de tarefa, das quais podemos citar algumas das mais famosas:

- Nessus
- Qualys
- Acunetix
- OpenVas
- Nexpose

Cada uma dessas ferramentas possui seu próprio motor de varredura, e identifica as vulnerabilidades de uma maneira diferente. Os fabricantes possuem bancos de dados de vulnerabilidades, nos quais armazena diversas informações sobre cada ameaça que sua ferramenta verifica. A representação de uma vulnerabilidade por uma ferramenta é denominada *plugin*. No escopo do presente trabalho, iremos utilizar os *plugins* do Nessus e do Qualys.

##### Nessus

O Nessus é uma das principais ferramentas de varredura de vulnerabilidades, e é desenvolvido pela Tenable[^tenable]. Atualmente, o Nessus conta com quase 120 mil *plugins*, que cobrem quase 50 mil CVE IDs[^plugininfo]. Um *plugin* do Nessus é composto, dentre outros, pelos seguintes atributos:

```
Id: identificador único do plugin
Name: título do plugin
BugTraq Id(s): identificador único do BugTraq
CVE Id(s): lista de CVE IDs associados ao plugin
Category: classificação do tipo da vulnerabilidade
Family: categoria a que o plugin pertence
Synopsis: breve descrição
Description: longa descrição
Severity: severidade do plugin, que varia de Informativo a Crítico
Published: data de publicação do plugin
Modified: última vez que o plugin foi publicado
Version: versão atual do plugin
X-Reference(s): outras referências associadas ao plugin
```

Exemplo de *plugin* Nessus:

```
Id: 10669
Name: A1Stats Multiple Script Traversal Arbitrary File Access
BugTraq Id(s): 2705
CVE Id(s): CVE-2001-0561
Category: remote
Family: CGI Abuses
Severity: Medium
```

##### Qualys

O Qualys é outra ferramenta de varredura de vulnerabilidades, desenvolvido pela empresa homónima[^qualys]. Sua base é composta por cerca de 34 mil *plugins*, que possuem os seguintes atributos:

```
QualysID: identificador único do plugin
Title: título do plugin
Sub Category: lista de categorias mais genéricas do plugin
Category: categoria mais específica do plugin
CVE ID: lista de CVE IDs associados ao plugin
Vendor Reference: identificador da vulnerabilidade nos boletins do fabricante da ferramenta vulnerável
CVSS: severidade do plugin
Bugtraq ID: identificador do BugTraq
Published: data de publicação do plugin
Modified: última vez que o plugin foi publicado
```

Exemplo de *plugin* do Qualys:

```
QualysID: 10340
Title: Drummon Miles A1Stats Directory Traversal Vulnerability
Sub Category: Remote Discovery, Patch Available, Exploit Available
Category: CGI
CVE ID: CVE-2001-0561
CVSS: 7.5
Bugtraq ID: 2705
```

##### Vulnerabilidades Duplicadas

Como pode ser visto no exemplo acima, ambas as ferramentas possuem sua própria representação da mesma vulnerabilidade. Quando uma empresa utiliza mais de uma ferramenta de varredura de vulnerabilidades, corre o risco de elencar as vulnerabilidades em duplicidade. O problema é que a correlação entre os diferentes *plugins* não é trivial. Apesar de haver, em alguns casos, bastante similaridade entre os *plugins*, em outros eles possuem informações bastante diferentes.

#### Mapeamento de Plugins de Diferentes Fontes

Para ajudar a sanar esse problema, a solução desenvolvida utiliza o processamento da linguagem natural para classificar a similaridade entre *plugins*. A princípio, três atributos são utilizados para a comparação: o título do plugin, a lista de CVE IDs e as Referências externas (incluindo o BugTraq ID).

A solução utiliza a linguagem de programação Python versão 3, o banco de dados MongoDB e as bibliotecas Pandas[^pandas], NLTK[^nltk] e Fuzzywuzzy[^fz].

##### Instalação

Para utilizar a ferramenta, é necessário instalar as ferramentas mencionadas (Python 3 e MongoDB).

A instalação das bibliotecas Python pode ser feita de forma automatizada, acessando o diretório da aplicação, com o comando:

```bash
$ pip3 install -r requirements.txt
```

##### Utilização

A ferramenta está dividida, essencialmente, em 3 partes: `metrics.py`, `parser.py` e `plugin.py`. Além disso, há os módulos auxiliares: `database.py` e `utils.py`. Na versão atual, a ferramenta irá calcular algumas métricas do conjunto de dados utilizados para os testes.

Para executar a ferramenta, basta aceder ao diretório raíz (onde encontra-se o README) e executar o comando:

```shell
$ python3 -m es_tpf
```

Ao executar o comando acima, as seguintes rotinas serão realizadas:

- Construção do Banco de Dados completo
- Construção do Banco de Dados para teste
- Geração das Métricas (interactivo)

##### Construção do Banco de Dados completo

Com o mongoDB instalado e a rodar na máquina local, a ferramenta irá gerar o banco de dados a partir dos ficheiros ` base-nessus-min.csv` e `base-qualys-min.csv`. Ambos encontram-se dentro do diretório `es_tpf/resources/`. Esse banco de dados possui cerca de 19 mil plugins (que foram selecionados manualmente dentre mais de 100 mil, para servir de amostragem para esse trabalho).

##### Construção do Banco de Dados para teste

A partir desses 19 mil plugins, foram selecionados 407, dos quais 275 fazem parte do grupo de Matches ou de Not Matches, e os outros 132 são aleatórios.

##### Geração de Métricas

Com a base de dados concluída, é possível gerar as métricas baseadas na Matriz de Confusão. O grupo de Matches possui 141 entradas, enquanto que o grupo de Not Matches possui 134 entradas (67 para cada *scanner*, Nessus e Qualys). Ou seja, o resultado perfeito seria ter 141 Verdadeiros-Positivos e 134 Verdadeiros-Negativos.

Para um uso real da ferramenta, contudo, o principal objetivo é ter o maior nível de exatidão possível com relação aos Verdadeiros-Positivos. Isso porque, para um analista ou empresa de Segurança da Informação, o que se procura é saber quais plugins de uma ferramenta correspondem a outros plugins de outra ferramenta.

Os resultados ficaram:

|              | Positivo | Negativo |
| :----------: | :------: | :------: |
| **Positivo** |   127    |    14    |
| **Negativo** |   124    |    9     |

Com isso, foi atingida uma precisão de 90%. Ou seja, a ferramenta acertou 90% dos Verdadeiros-Positivo (que é a principal métrica para esse caso concreto).

**Conclusão e Trabalho Futuro**

Com a realização desse trabalho, foi possível perceber um grande potencial da ferramenta para solucionar o problema identificado. Na versão atual, a ferramenta ainda apresenta algumas falhas, principalmente no tocante a *True Negatives* e *False Negatives*, o que afeta a métrica do *Recall*. Porém, foi possível vislumbrar a medida de *Precision* de 90%, o que é um resultado bastante expressivo.

Como trabalho futuro, é pertinente analisar os *thresholds* para *matches* e *não matches*, bem como ajustar a fórmula matemática que faz o cálculo da similaridade. Além disso, é possível analisar outros atributos dos *plugins*, além dos três que foram utilizados nesse trabalho. Por fim, a ferramenta poderá ser melhorada consideravelmente utilizando técnicas de *Machine Learning* e *Data Mining*.

[^tenable]: https://www.tenable.com/products/nessus/nessus-professional
[^plugininfo]: https://www.tenable.com/plugins
[^qualys]: https://www.qualys.com/apps/vulnerability-management/
[^pandas]: https://pandas.pydata.org/
[^nltk]: https://www.nltk.org/
[^fz]: https://github.com/seatgeek/fuzzywuzzy

