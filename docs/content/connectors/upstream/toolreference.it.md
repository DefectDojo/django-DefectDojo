---
title: Guida di riferimento per gli strumenti degli Upstream Connector
description: Il nostro elenco di strumenti Connector supportati e come configurarli
  con DefectDojo
aliases:
- /it/import_data/pro/connectors/connectors_tool_reference/
- /it/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: gli Upstream Connector sono una funzionalità esclusiva di DefectDojo Pro.</span>

Quando configuri un Connector per uno strumento supportato, dovrai fornire a DefectDojo informazioni specifiche relative all'API dello strumento. Come minimo, ti serviranno:

* **Posizione** - un campo che generalmente si riferisce all'URL del tuo strumento nella tua rete,
* **Segreto** - generalmente una chiave API.

Alcuni strumenti richiedono campi aggiuntivi relativi all'API oltre a **Posizione** e **Segreto**. Potrebbero inoltre richiedere modifiche dal loro lato per accogliere un Connector in arrivo da DefectDojo.

![image](images/connectors_tool_reference.png)

Ogni strumento ha una configurazione API diversa, e questa guida ha lo scopo di aiutarti a configurare l'API dello strumento in modo che DefectDojo possa connettersi.

Quando possibile, ti consigliamo di creare un nuovo account 'DefectDojo Bot' all'interno del tuo strumento di sicurezza, da utilizzare esclusivamente per il Connector. Questo ti aiuterà a distinguere meglio le azioni eseguite manualmente dal tuo team dalle azioni automatiche eseguite dal Connector.

# **Asset Connector**

La maggior parte dei Connector importa i **riscontri** da uno strumento di sicurezza. Gli **Asset Connector** funzionano in modo diverso: importano invece il tuo **inventario degli asset**. Un Asset Connector enumera gli asset presenti su una piattaforma esterna (ad esempio, i repository in un gruppo GitLab) e crea e mantiene automaticamente i **Prodotti** (Asset) e i **Tipi di Prodotto** (Organizzazioni) corrispondenti in DefectDojo. Nessun riscontro viene importato da un Asset Connector.

* **Discover** e **Sync** riconciliano entrambi l'elenco degli asset. I nuovi asset appaiono come Record `NEW`; una volta mappati (automaticamente, se l'auto-mapping è abilitato), DefectDojo crea il Prodotto e lo raggruppa sotto un Tipo di Prodotto derivato dallo strumento — ad esempio, il namespace di GitLab o il progetto di Azure DevOps.
* Se un asset viene successivamente rimosso a monte (ad esempio, un repository viene eliminato), il suo Record mappato viene contrassegnato come `MISSING` alla Sync successiva, in modo che il tuo team possa valutarlo. DefectDojo non elimina mai silenziosamente un Prodotto.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets e ServiceNow CMDB sono Asset Connector. runZero è principalmente un Asset Connector, ma può opzionalmente importare le vulnerabilità come riscontri. Tutti gli altri Connector elencati di seguito importano riscontri.

# **Connector supportati**

## **Acunetix 360**

Il connector Acunetix 360 importa i **riscontri di vulnerabilità DAST** dalla piattaforma cloud Acunetix 360 (la piattaforma Invicti). DefectDojo rileva i siti web scansionati del tuo account e crea un Record per ogni **sito web**; i riscontri di un sito web provengono dalla sua ultima scansione completata.

**Nota bene:** questo connector è per **Acunetix 360** (il prodotto cloud all'indirizzo `online.acunetix360.com`). Non è destinato allo scanner on-premises Acunetix Standard/Premium, che ha un'API diversa.

#### Prerequisiti

Un account Acunetix 360 e una **credenziale API**: in Acunetix 360, apri il menu del tuo account > **API Settings**, quindi annota l'**API User ID** e genera un **API Token**. Il connector si autentica con queste credenziali come HTTP Basic, quindi si consiglia un account di servizio dedicato per distinguere l'attività automatizzata dalle azioni manuali del team.

#### Mappature del Connector

1. Inserisci l'URL del tuo Acunetix 360 nel campo **Posizione**: `https://online.acunetix360.com`.
2. Inserisci l'API User ID nel campo **API User ID**.
3. Inserisci l'API Token nel campo **API Token**.
4. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Ogni sito web scansionato diventa un Record. I riscontri provengono dall'ultima scansione completata del sito web; le vulnerabilità che Acunetix 360 ha contrassegnato come **Rischio accettato** o **Falso positivo** vengono comunque importate ma segnalate come inattive (rischio accettato o falso positivo), in modo che il Prodotto DefectDojo rifletta la valutazione del fornitore.

## **Akamai API Security**

Il connector Akamai API Security utilizza una chiave API per recuperare i riscontri di sicurezza dall'API di Akamai. DefectDojo rileverà il tuo ambiente Akamai e creerà Record separati per ogni **Applicazione** e **Host** configurati nel tuo account.

#### Prerequisiti

Avrai bisogno di una chiave API con accesso all'API di Akamai. Consigliamo di creare un account di servizio dedicato per DefectDojo, per distinguere chiaramente l'attività automatizzata dalle azioni manuali del team.

#### Mappature del Connector

1. Inserisci l'URL di base della tua API Akamai nel campo **Posizione**. Questo URL è specifico per la tua istanza Akamai: ad esempio
2. Inserisci una **Chiave API** valida nel campo **Segreto**.

DefectDojo mapperà le **Applicazioni** e gli **Host** come Record separati. Ogni Applicazione apparirà come `{name} (application)` e ogni Host come `{name} (host)` nel tuo elenco di Record.

## **Anchore**

Il connector Anchore utilizza il token API di un utente per recuperare i dati da Anchore Enterprise. I Prodotti vengono mappati e rilevati in base alle "Applicazioni", che sono composte da più immagini in Anchore - consulta la [documentazione di Anchore Enterprise](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) per maggiori informazioni.

#### Mappature del Connector

1. L'URL di Anchore nel campo **Posizione**: questo è l'URL con cui accedi ad Anchore.
2. Inserisci una chiave API valida nel campo Segreto. Questa è la chiave API associata al tuo account Burp Service.

Consulta la [documentazione ufficiale di Anchore](https://docs.anchore.com/current/docs/) per maggiori informazioni sulla creazione di un token per Anchore.

## **AWS Security Hub**

Il connector AWS Security Hub utilizza una chiave di accesso AWS per interagire con le API di Security Hub.

#### Prerequisiti

Anziché utilizzare la chiave di accesso AWS di un membro del team, ti consigliamo di creare un IAM User nel tuo account AWS specificamente per DefectDojo, con i permessi di questo utente limitati a quelli necessari per interagire con Security Hub.

La policy AWS "**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**" fornisce il livello di accesso richiesto per un connector. Se desideri scrivere una policy personalizzata per un Connector, dovrai includere i seguenti permessi:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Una definizione di policy funzionante potrebbe avere il seguente aspetto:

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Nota bene:** in futuro potremmo aver bisogno di utilizzare azioni API aggiuntive per offrire la migliore esperienza possibile, il che richiederà aggiornamenti a questa policy.

Dopo aver creato il tuo IAM user e avergli assegnato i permessi necessari tramite una policy/ruolo appropriata, dovrai generare una chiave di accesso, che potrai poi utilizzare per creare un Connector.

#### Mappature del Connector

1. Inserisci l'[endpoint API AWS per la tua regione](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) appropriato nel campo **Posizione**: ad esempio, per recuperare i risultati dalla regione `us-east-1`, dovresti fornire

`https://securityhub.us-east-1.amazonaws.com`
2. Inserisci una **Chiave di accesso AWS** valida nel campo **Chiave di accesso**.
3. Inserisci una **Chiave segreta** corrispondente nel campo **Chiave segreta**.

DefectDojo può recuperare i Riscontri da più di una regione utilizzando la funzionalità di **aggregazione cross-region** di Security Hub. Se l'[aggregazione cross-region](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) è abilitata, dovresti fornire l'endpoint API per la tua "**regione di aggregazione**". Per le regioni collegate aggiuntive, DefectDojo creerà i relativi Product Record in base all'ID del tuo account AWS e al nome della regione.

## **Azure DevOps**

Il connector Azure DevOps è un **Asset Connector**: enumera i repository git in ogni progetto della tua organizzazione Azure DevOps e crea un Asset DefectDojo per ogni repository, raggruppato in Organizzazioni in base al progetto Azure DevOps. Non viene importato alcun riscontro.

#### Prerequisiti

Avrai bisogno di un Personal Access Token (PAT) per l'organizzazione. Ti consigliamo di creare il token da un account di servizio dedicato. Sono richiesti solo scope di lettura:

1. In Azure DevOps, apri **User settings > Personal access tokens > New Token**.
2. Fai clic su **Show all scopes**, quindi seleziona **Code: Read** e **Project and Team: Read**.

È supportato solo Azure DevOps Services (dev.azure.com); Azure DevOps Server on-premise non è al momento supportato.

#### Mappature del Connector

1. Inserisci l'URL della tua organizzazione nel campo **Posizione**: `https://dev.azure.com/{your-organization}`. Sono accettati anche i vecchi URL `https://{your-organization}.visualstudio.com`, e gli eventuali segmenti di percorso aggiuntivi (ad esempio, un link a un progetto specifico) vengono ignorati.
2. Inserisci il PAT nel campo **Segreto**.

Ogni repository diventa un Record con lo stesso nome del repository, raggruppato in base al suo **progetto** Azure DevOps. I repository disabilitati vengono ignorati, quindi disabilitare o eliminare un repository contrassegna il suo Record come `MISSING` alla Sync successiva.

## **Backstage**

Il connector Backstage è un **asset connector**: anziché importare Riscontri, importa il tuo Software Catalog di [Backstage](https://backstage.io) in DefectDojo e mantiene sincronizzata la gerarchia dei Prodotti e la proprietà dei team con esso. È progettato per le organizzazioni che mantengono il proprio inventario dei servizi e la propria struttura organizzativa in Backstage e vogliono che DefectDojo rispecchi quella struttura invece di doverla gestire manualmente.

#### Cosa viene mappato

| Backstage | DefectDojo |
|---|---|
| **System** | Tipo di Prodotto (i Component senza System sono raggruppati sotto un Tipo di Prodotto configurabile "Backstage / Uncategorized") |
| **Component** | Prodotto — con il nome preso dal `title` dell'entità (con fallback su `name`), con la descrizione del catalogo |
| **Owning Group** (relazione `ownedBy`) | Un Gruppo DefectDojo collegato al Prodotto (ruolo predefinito: Maintainer, configurabile) |
| **Owner email** (email del profilo Group, o email di un Utente owner) | Un Membro del Prodotto, quando esiste già un utente DefectDojo con quell'email (gli utenti non vengono mai creati) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Tag del Prodotto con prefisso `backstage:` |
| `metadata.annotations` | Memorizzato sul Record (con limite); alcune annotazioni selezionate possono essere promosse ad attributi di prima classe o a tag tramite **Mappature delle annotazioni** |

I Record sono identificati in base al `metadata.uid` assegnato dal server dell'entità, quindi le rinomine in Backstage aggiornano il Prodotto mappato **sul posto** alla sync successiva — senza duplicati. Il nome del Prodotto segue sempre il catalogo: per rinominare un Prodotto gestito da questo connector, rinomina il Component in Backstage (una rinomina lato DefectDojo, o un nome personalizzato assegnato durante la mappatura manuale, viene riconciliata con il nome del catalogo alla sync successiva, a meno che non entri in conflitto con un altro Prodotto). I cambi di proprietà spostano l'assegnazione del gruppo del Prodotto. I Component che scompaiono dal catalogo (o che vengono contrassegnati con l'annotazione `backstage.io/orphan`) vengono marcati come **MISSING** — DefectDojo non elimina mai un Prodotto autonomamente. La gerarchia di Domain e Group (i team superiori) viene registrata solo come tag/metadati; non crea ulteriori livelli di gerarchia.

#### Prerequisiti

Il connector si autentica con un **token di accesso esterno statico** contro il backend di Backstage. Nella configurazione della tua app Backstage, definisci un token e (consigliato) limitane l'ambito al plugin catalog:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Genera un token casuale robusto (ad esempio `openssl rand -hex 32`) e memorizzalo nell'ambiente del tuo deployment Backstage. Consulta la [documentazione di Backstage sull'autenticazione service-to-service](https://backstage.io/docs/auth/service-to-service-auth) per i dettagli.

#### Mappature del Connector

1. Inserisci l'**URL radice del backend di Backstage** nel campo **Posizione**: ad esempio `https://backstage.example.com` (il connector aggiunge `/api/catalog`). Deve essere l'URL del **backend**, non l'interfaccia web frontend.
2. Inserisci il token di accesso esterno statico nel campo **Segreto**.

Campi facoltativi (lascia vuoto per i valori predefiniti):

* **Namespace** — namespace del catalogo separati da virgola da importare; se vuoto, importa ogni namespace.
* **Tipi di componente** — valori `spec.type` separati da virgola (ad es. `service,website`); se vuoto, importa ogni tipo.
* **Dimensione pagina** — dimensione della pagina per le query al catalogo (1-500, predefinito 250).
* **Verifica TLS** — imposta su `false` solo se Backstage utilizza un certificato che DefectDojo non può verificare (CA interna); non consigliato.
* **Tipo di Prodotto non categorizzato** — il Tipo di Prodotto utilizzato per i Component senza System (predefinito `Backstage / Uncategorized`).
* **Ruolo del gruppo proprietario** — il ruolo concesso al team proprietario sui Prodotti mappati (predefinito `Maintainer`).
* **Mappature delle annotazioni** — un oggetto JSON che mappa le chiavi delle annotazioni ai nomi degli attributi del Record, oppure a `"tag"` per importare un'annotazione come tag del Prodotto, ad es. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Con **Auto-Map** abilitato, una singola Discover + Sync costruisce l'intera struttura di Tipo di Prodotto / Prodotto / proprietà senza passaggi manuali. Con Auto-Map disabilitato, i Component rilevati appaiono come Record in attesa della tua decisione di mappatura.

#### Limitazioni (v1)

* **L'appartenenza ai Group di Backstage non viene sincronizzata**: il connector crea/collega il team proprietario come Gruppo DefectDojo, ma popolare gli utenti di quel gruppo è lasciato al tuo identity provider o agli amministratori.
* Solo i Component diventano Prodotti; API, Resource e Domain non vengono importati come asset (i domain emergono come tag).
* I tag e le annotazioni vengono normalizzati e limitati per rispettare i limiti dei campi di DefectDojo (i valori troppo grandi vengono troncati).

**Una nota sulla direzione inversa:** mostrare i riscontri e i voti di DefectDojo *all'interno* di Backstage (nelle pagine delle entità) è un naturale sviluppo futuro che verrebbe realizzato come plugin frontend di Backstage che consuma la REST API di DefectDojo — è deliberatamente fuori ambito per questo connector, che importa in DefectDojo solo i dati del catalogo.

## **Black Duck**

Il connector Black Duck importa i riscontri di **software composition analysis (SCA)** da un'istanza Black Duck Hub (Synopsys / Black Duck). DefectDojo rileva ogni progetto nell'istanza e crea un Record per ogni **progetto**; i riscontri di un progetto provengono dai componenti BOM vulnerabili della sua versione selezionata.

#### Prerequisiti

Un **token API** di Black Duck per un utente che possa vedere i progetti che vuoi importare. In Black Duck, apri il menu utente > **My Access Tokens** > **Create New Token**, concedigli (almeno) l'accesso in lettura, e copia il token quando viene mostrato — viene visualizzato una sola volta. Il connector scambia questo token con un bearer a breve durata a ogni sync; non viene mai memorizzato in chiaro al di fuori del campo segreto del connector.

#### Mappature del Connector

1. Inserisci l'URL del tuo hub Black Duck nel campo **Posizione** — ad esempio `https://your-company.app.blackduck.com`.
2. Inserisci il token API nel campo **Segreto**.
3. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Ogni progetto Black Duck diventa un Record. Per impostazione predefinita, il connector importa la versione **released** del progetto (con fallback sulla sua prima versione); ogni componente BOM vulnerabile di quella versione diventa un riscontro, con titolo `{vulnerability} in {component}:{version}`.

Questo connector è distinto dai parser Black Duck basati su file — i suoi riscontri utilizzano il tipo di scansione dedicato **Black Duck - Connectors Import**.

## **Bitbucket**

Il connector Bitbucket è un **Asset Connector**: enumera i repository nei workspace di Bitbucket Cloud che indichi e crea un Asset DefectDojo per ogni repository, raggruppato in Organizzazioni in base al progetto Bitbucket. Non viene importato alcun riscontro.

#### Prerequisiti

Bitbucket Cloud richiede un token API Atlassian **con scope** — i token API Atlassian classici (senza scope) vengono rifiutati da Bitbucket con un errore "API Token provided has no Bitbucket scopes".

1. Vai su [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) e scegli **Create API token with scopes**.
2. Seleziona l'app **Bitbucket**, quindi concedi gli scope di lettura: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` e `read:project:bitbucket`.

È supportato solo Bitbucket Cloud (bitbucket.org). Bitbucket Server ha raggiunto l'end of life nel 2024, e Bitbucket Data Center non è supportato.

#### Mappature del Connector

1. Inserisci `https://bitbucket.org` nel campo **Posizione**.
2. Inserisci l'email dell'account Atlassian a cui appartiene il token nel campo **Email**.
3. Inserisci il token API con scope nel campo **Segreto**.
4. Inserisci uno o più slug di workspace (separati da virgola) nel campo **Slug degli spazi di lavoro**. Questo campo è obbligatorio: i token API con scope di Bitbucket non possono elencare automaticamente i workspace, quindi DefectDojo deve sapere quali workspace leggere.

Ogni repository diventa un Record con lo stesso nome del repository, raggruppato in base al suo **progetto** Bitbucket.

## **Bugcrowd**

Il connector Bugcrowd utilizza la REST API di Bugcrowd per importare le segnalazioni dai tuoi programmi di bug bounty e di divulgazione delle vulnerabilità. DefectDojo rileva i programmi a cui il tuo token API può accedere e crea un Record per ciascuno, importando le segnalazioni di quel programma come riscontri.

#### Prerequisiti

Avrai bisogno di un **token API** di Bugcrowd con accesso ai programmi che vuoi importare. Ti consigliamo di creare un account di servizio dedicato per DefectDojo così l'attività automatizzata sarà facile da distinguere dalle azioni manuali del team. Genera il token in Bugcrowd sotto **Organization settings > API credentials**; è sufficiente l'accesso in lettura a segnalazioni, programmi e target.

#### Mappature del Connector

1. Inserisci `https://api.bugcrowd.com` nel campo **Posizione**.
2. Inserisci il tuo token API di Bugcrowd nel campo **Segreto**. Viene inviato come header `Authorization: Token`.
3. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Ogni **programma** Bugcrowd diventa un Record, e le sue segnalazioni vengono importate come riscontri mantenendo la gravità assegnata da Bugcrowd. Le segnalazioni duplicate vengono escluse, quindi la reimportazione non crea riscontri ripetuti per lo stesso problema.

## **Bright Security**

Il connector Bright Security utilizza l'API di [Bright](https://brightsec.com) (in precedenza NeuraLegion) per importare **riscontri DAST**. DefectDojo rileva ogni scansione a cui il token può accedere e crea un Record per ogni scansione completata, quindi importa i problemi di quella scansione come riscontri.

#### Prerequisiti

Avrai bisogno di una **chiave API** di Bright, creata nell'app Bright sotto **User settings → API keys** (una chiave `Org` o personale). La chiave viene inviata nell'header `Authorization: Api-Key` e non viene mai registrata nei log.

#### Mappature del Connector

1. Lascia vuoto il campo **Posizione** per usare `https://app.brightsec.com`, oppure inserisci esplicitamente il tuo host Bright.
2. Inserisci la chiave API di Bright nel campo **Segreto**.
3. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

DefectDojo mappa ogni **scansione** completata a un Record e ogni **problema** a un riscontro: la gravità proviene dalla valutazione propria di Bright (Critica/Alta/Media/Bassa), il punteggio CVSS, il CWE e la remediation vengono riportati, il punto di ingresso interessato diventa l'endpoint, e le evidenze di richiesta/risposta sono incluse nella descrizione. I riscontri vengono registrati come riscontri dinamici e deduplicati in base all'id del problema di Bright.

Consulta la [documentazione API di Bright](https://docs.brightsec.com/) per maggiori informazioni.

## **BurpSuite**

Il connector Burp di DefectDojo chiama la GraphQL API di Burp per recuperare i dati.

#### Prerequisiti

Prima di poter configurare questo connector, avrai bisogno di una chiave API da un Burp Service Account. Gli account utente di Burp non dispongono di chiavi API per impostazione predefinita, quindi potrebbe essere necessario creare un nuovo utente specificamente per questo scopo.

Consulta la [documentazione di Burp](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) per una guida sulla configurazione di un utente Service Account con una chiave API.

#### Mappature del Connector

1. Inserisci l'URL radice di Burp nel campo **Posizione**: questo è l'URL con cui accedi allo strumento Burp.
2. Inserisci una Chiave API valida nel campo Segreto. Questa è la chiave API associata al tuo account Burp Service.

Consulta la [documentazione ufficiale di Burp](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) per maggiori informazioni sull'API di Burp.

## **Censys**

Il connector Censys legge gli asset host dalla Censys Platform e importa i servizi esposti di ogni host come riscontri. Utilizza l'API di ricerca globale della Censys Platform per enumerare gli host a cui lo limiti.

#### Prerequisiti

Avrai bisogno di un account **Platform** di Censys con accesso API:

* Un **Personal Access Token**, creato nella Censys Platform Console sotto Personal Access Tokens.
* Il tuo **ID organizzazione**, mostrato nella stessa pagina delle impostazioni sotto "Current Organization". L'accesso API all'endpoint di ricerca richiede un'organizzazione, quindi è necessario un piano Starter o superiore. I token del piano gratuito non hanno un ID organizzazione e non possono utilizzare l'API di ricerca.

I dati di CVE e rischio per singolo host sono disponibili solo nei piani Censys Core (enterprise), quindi nei piani inferiori i riscontri rappresentano servizi esposti anziché vulnerabilità.

Consulta la [documentazione dell'API di Censys Platform](https://docs.censys.com/reference/get-started) per maggiori informazioni.

#### Mappature del Connector

1. Inserisci `https://api.platform.censys.io` nel campo **Posizione**.
2. Inserisci il tuo Personal Access Token nel campo **Chiave API**.
3. Inserisci il tuo **ID organizzazione**.
4. Inserisci una **Query di ricerca** che limiti l'importazione ai tuoi asset, ad esempio `host.autonomous_system.asn: <your ASN>` oppure `host.ip: 203.0.113.0/24`.
5. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

DefectDojo crea un Record per ogni host e importa i suoi servizi esposti come riscontri.

## **Checkmarx ONE**

Il connector Checkmarx ONE di DefectDojo chiama l'API di Checkmarx per recuperare i dati.

#### **Mappature del Connector**

1. Inserisci il tuo **nome del tenant** nel campo **Checkmarx Tenant**. Questo nome dovrebbe essere visibile nell'angolo in alto a destra della pagina di login di Checkmarx ONE:
" Tenant: \<**il tuo nome del tenant**\> "
​
![image](images/connectors_tool_reference_2.png)

2. Inserisci una chiave API valida. Potrebbe essere necessario generarne una nuova: consulta la [documentazione API di Checkmarx](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) per i dettagli.
3. Inserisci la posizione del tuo tenant nel campo **Posizione**. Questo URL è formattato come segue:
​`https://<your-region>.ast.checkmarx.net/` . La tua regione si trova all'inizio dell'URL di Checkmarx quando utilizzi l'app Checkmarx. **<https://ast.checkmarx.net>** è il server primario US (che non ha un prefisso di regione).

#### **Gestione dei branch**

Per impostazione predefinita, ogni sync importa i riscontri della **singola scansione completata più recente di un progetto, indipendentemente dal branch**. Se la tua CI scansiona molti branch, qualsiasi branch abbia effettuato la scansione per ultimo "vince" quella sync: i riscontri che esistono solo su altri branch non vengono importati, e la riconciliazione close-old della sync può aprire e chiudere ciclicamente i riscontri man mano che branch diversi si alternano nell'essere la scansione più recente.

Due campi facoltativi controllano questo comportamento:

- **Branch**: fissa ogni progetto a un unico nome di branch — vengono importate solo le scansioni di quel branch. Questo è un valore globale unico per l'intero connector, quindi si adatta bene ai parchi progetti in cui ogni progetto utilizza lo stesso branch di lunga durata (ad es. `main`).
    - È supportato un **carattere wildcard `*`**. Un valore di Branch contenente `*` seleziona *ogni* branch corrispondente invece di uno solo — ad esempio `release/*` importa ogni branch di release, e `*` corrisponde a ogni branch. Combinato con **Tracciamento dei branch scansionati**, questo è il modo per tracciare una famiglia di branch senza tracciarli tutti.
    - Se un wildcard non corrisponde a **nessun** branch entro la finestra di scansione, quella sync viene **saltata** anziché essere trattata come "il branch non ha riscontri" — quindi uno schema che temporaneamente non corrisponde a nulla non può chiudere tutti i riscontri sull'asset.
- **Tracciamento dei branch scansionati**: quando abilitato, ogni sync trova ogni branch con una scansione completata nella cronologia recente delle scansioni del progetto e importa **l'ultima scansione completata di ogni branch**, con una reimportazione per branch. I riscontri di ogni branch vivono in un proprio engagement sull'asset mappato, denominato "\<engagement predefinito\> \- \<branch\>", quindi la chiusura dei riscontri obsoleti è delimitata per branch: una correzione unita in un branch non può mai chiudere i riscontri di un altro branch. Il branch primario del progetto (come riportato da Checkmarx) viene importato per primo, quindi le ricorrenze dello stesso riscontro su altri branch vengono deduplicate rispetto all'originale del branch primario.

Note su **Tracciamento dei branch scansionati**:

- **Verifica quale impostazione predefinita si applica a te.** Il tracciamento dei branch è **attivo per impostazione predefinita nelle nuove installazioni**. Le installazioni precedenti a questa modifica mantengono il comportamento precedente, quindi per loro l'interruttore è disattivato finché qualcuno non lo attiva.
- Quando entrambi i campi sono impostati, viene tracciato solo il **Branch** fissato — anche quando quel valore di Branch è uno schema wildcard, nel qual caso viene tracciato ogni branch corrispondente allo schema.
- Un branch che smette di essere scansionato (unito o eliminato) smette di ricevere aggiornamenti: il suo engagement rimane visibile con i suoi ultimi riscontri noti, che puoi rivedere e chiudere in blocco.
- Disattivare successivamente l'interruttore è sicuro: gli engagement per branch smettono semplicemente di ricevere importazioni e l'engagement predefinito riprende alla sync successiva.
- I Connector riconciliano lo stato secondo la pianificazione della sync. Il tracciamento dei branch fa sì che ogni sync sia completa tra i branch; non rende i dati in tempo reale tra una sync e l'altra.

## **Cloudflare**

Il connector Cloudflare importa gli **insight del Security Center** — problemi di postura di sicurezza che Cloudflare segnala sul tuo account e sulle tue zone, come un record DMARC mancante, il DNSSEC non abilitato, o un problema di certificato. DefectDojo crea un Record per ogni zona (dominio) che presenta insight aperti, oltre a un Record a livello di account per gli insight non legati a una zona specifica.

#### Prerequisiti

Avrai bisogno di un **token API** di Cloudflare (non la Global API Key legacy). Creane uno sotto **My Profile > API Tokens > Create Token** nella dashboard di Cloudflare. L'opzione più rapida è il modello **"Read all resources"**; per un token con privilegi minimi, concedi **Zone > Zone > Read** (tutte le zone) più l'accesso in lettura a livello di account per il Security Center.

#### Mappature del Connector

1. Inserisci `https://api.cloudflare.com/client/v4` nel campo **Posizione**.
2. Inserisci il token API nel campo **Segreto**.
3. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

DefectDojo rileva automaticamente gli account e le zone a cui il token può accedere — non è richiesto alcun ID account. Vengono importati solo gli insight aperti (attivi, non ignorati), quindi gli insight che risolvi o ignori in Cloudflare vengono automaticamente mitigati in DefectDojo alla sync successiva.

## **Cobalt.io**

Il connector Cobalt.io utilizza l'API di Cobalt.io (v2) per recuperare i riscontri dei pentest dalla tua organizzazione Cobalt.io. DefectDojo individua ogni organizzazione a cui il tuo token API può accedere e crea un Record separato per ogni **asset** (l'unità sottoposta a pentest da Cobalt).

#### Prerequisiti

È necessario un **token API personale** di Cobalt.io. Consigliamo di creare un account di servizio dedicato per DefectDojo, in modo da distinguere chiaramente l'attività automatizzata dalle azioni manuali del team. Genera un token da **Settings \> API Tokens** nell'interfaccia di Cobalt.io. I token delle organizzazioni vengono individuati automaticamente \- non è necessario fornirli.

#### Mappature del Connector

1. Inserisci l'URL di base dell'API di Cobalt.io nel campo **Percorso**: `https://api.cobalt.io` (o il tuo host regionale, ad esempio `https://api.us.cobalt.io`).
2. Inserisci il tuo **token API personale** nel campo **Secret**.
3. Facoltativamente, inserisci un **Token dell'organizzazione** per vincolare la sincronizzazione a una singola organizzazione. Se lasciato vuoto, DefectDojo sincronizza ogni organizzazione a cui il token API personale può accedere.

DefectDojo mappa ogni **asset** di Cobalt.io come Record separato. I riscontri vengono importati per ogni asset mappato, con il rispettivo stato Cobalt.io (ad esempio `valid_fix`, `wont_fix`, `invalid`) che determina lo stato del riscontro in DefectDojo.

## **Contrast**

Il connector Contrast utilizza l'API REST Contrast Assess per importare le vulnerabilità delle applicazioni. DefectDojo individua le applicazioni nella tua organizzazione Contrast e crea un Record per ciascuna.

#### Prerequisiti

Sono necessari quattro valori da Contrast. Consigliamo di creare un account di servizio dedicato, in modo che l'attività automatizzata sia facilmente distinguibile dalle azioni manuali del team. Nell'interfaccia di Contrast, in **User Settings > Profile > Your Keys**, puoi trovare:

* La **Chiave API** dell'organizzazione.
* La tua **Chiave di servizio** personale.
* Lo **username** a cui appartengono le credenziali (l'email di accesso dell'account).
* Il tuo **ID organizzazione** — lo UUID dell'organizzazione da cui importare, mostrato anche in **Organization Settings**.

#### Mappature del Connector

1. Inserisci nel campo **Percorso** l'URL di base che utilizzi per accedere a Contrast — per il prodotto in hosting è tipicamente `https://app.contrastsecurity.com` (oppure l'URL del tuo Team Server regionale / self-hosted).
2. Inserisci l'email di accesso dell'account nel campo **Username**.
3. Inserisci la **Chiave API** dell'organizzazione nel campo **Chiave API**.
4. Inserisci la **Chiave di servizio** personale nel campo **Chiave di servizio**.
5. Inserisci l'**ID organizzazione** (UUID) nel campo **ID organizzazione**.
6. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Ogni applicazione Contrast diventa un Record e le sue vulnerabilità vengono importate come riscontri.

## **Coverity**

Il connector Coverity importa i riscontri da un server **Coverity Connect**. DefectDojo crea un Record per ogni **progetto** Coverity.

#### Mappature del Connector

1. Inserisci l'URL del server Coverity Connect nel campo **Percorso**.
2. Inserisci lo **username** di Coverity Connect nel campo **Username**.
3. Inserisci la password dell'utente o la chiave di autenticazione nel campo **Secret**.
4. Facoltativamente, imposta un **Nome vista** per selezionare quale vista dei problemi salvata legge il connector. Lascia vuoto per utilizzare quella predefinita, **Outstanding Issues**.
5. Facoltativamente, imposta **Importa tutti i tipi di problema** su `true` per estendere l'importazione oltre il filtro predefinito dei problemi di sicurezza e qualità (`RESOURCE_LEAK`).

## **CrowdStrike Falcon**

Il connector CrowdStrike Falcon importa le **vulnerabilità Spotlight** e i **rilevamenti EDR** dalla piattaforma Falcon, come due tipi di riscontro separati (`CrowdStrike:Spotlight` e `CrowdStrike:Detections`). DefectDojo crea un Record per ogni **host** Falcon.

#### Prerequisiti

Un **client API** Falcon (Client ID e secret), creato nella console Falcon in **Support \> API Clients and Keys**. Assegnagli gli ambiti per i dati che vuoi importare: **Hosts: Read** (obbligatorio, per il rilevamento degli host), **Vulnerabilities (Spotlight): Read** (per i riscontri Spotlight), e **Alerts: Read** (per i rilevamenti EDR). I due tipi di riscontro sono indipendenti — se al client manca un ambito, quel tipo di riscontro viene saltato invece di far fallire la sincronizzazione, quindi un client senza **Alerts: Read** importa comunque le vulnerabilità Spotlight.

#### Mappature del Connector

1. Inserisci l'URL di base dell'API del tuo cloud Falcon nel campo **Percorso**, corrispondente alla regione della tua console — ad esempio `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1), oppure `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Inserisci il Client ID del client API nel campo **Client ID**.
3. Inserisci il secret del client API nel campo **Client Secret**.
4. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Ogni host Falcon diventa un Record, denominato in base a hostname, sistema operativo e tipo. Vengono importate solo le vulnerabilità Spotlight **aperte** e **riaperte**, quindi una nuova importazione chiude i riscontri risolti.

## **Deepfence ThreatMapper**

Il connector Deepfence ThreatMapper utilizza l'API REST della console di gestione di [ThreatMapper](https://github.com/deepfence/ThreatMapper) per importare i risultati delle **scansioni di vulnerabilità**. DefectDojo individua ogni nodo che ThreatMapper ha scansionato — un'immagine container, un host o un container — e crea un Record per ciascuno, quindi importa come riscontri l'ultima scansione completata di quel nodo.

#### Prerequisiti

È necessario un **token API** di ThreatMapper, disponibile nella console in **Settings → User Management** (la chiave API del tuo utente). Il connector lo scambia con un token di accesso di breve durata a ogni sincronizzazione; il token API non viene mai registrato nei log.

#### Mappature del Connector

1. Inserisci l'URL della console ThreatMapper nel campo **Percorso** (ad esempio `https://threatmapper.example.com`).
2. Nel campo **Secret**, inserisci il token API di ThreatMapper.
3. Se la tua console utilizza un certificato autofirmato, imposta **Skip TLS Verification** su `true`.
4. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

DefectDojo mappa ogni **nodo** analizzato come Record e ogni **CVE** presente nell'ultima scansione di vulnerabilità completata come riscontro. La gravità deriva dalla valutazione propria di ThreatMapper, e vengono riportati il pacchetto interessato, il punteggio CVSS, la versione della correzione (come mitigazione), i link di riferimento e un blocco di dettagli. I riscontri vengono registrati come riscontri dinamici e deduplicati in base a nodo, CVE, pacchetto e percorso del pacchetto.

Per maggiori informazioni, consulta la [documentazione di ThreatMapper](https://community.deepfence.io/threatmapper/docs/v2.5/).

## Dependency\-Track

Questo connector recupera i dati da un'istanza Dependency\-Track on\-premise, tramite API REST.

​**Mappature del Connector**

1. Inserisci l'URL del tuo server Dependency\-Track locale nel campo **Percorso**.
2. Inserisci una chiave API valida nel campo **Secret**.

Per generare una chiave API di Dependency\-Track:

1. **Gestione degli accessi**: vai su Administration \> Access Management \> Teams nell'interfaccia di Dependency\-Track.
2. **Configurazione dei team**: puoi creare un nuovo team oppure selezionarne uno esistente. I team ti permettono di gestire l'accesso alle API in base all'appartenenza al gruppo.
3. **Generazione della chiave API**: nella pagina dei dettagli del team selezionato, trova la sezione "API Keys". Fai clic sul pulsante \+ per generare una nuova chiave API.
4. **Assegnazione delle autorizzazioni**: nella sezione "Permissions" della pagina del team, fai clic sul pulsante \+ per aprire il selettore delle autorizzazioni. Scegli le autorizzazioni **VIEW\_PORTFOLIO** e **VIEW\_VULNERABILITY** per abilitare l'accesso API ai portfolio dei progetti e ai dettagli delle vulnerabilità.
5. Fai clic su "**Select**" per confermare e salvare queste autorizzazioni.

Per maggiori informazioni, consulta la **[documentazione di Dependency\-Track](https://docs.dependencytrack.org/integrations/rest-api/)**.

## **Docker Scout**

Il connector Docker Scout utilizza l'API dell'esportatore di metriche di Docker Scout per segnalare la postura di vulnerabilità delle immagini della tua organizzazione. DefectDojo individua ogni stream di Docker Scout (i tuoi ambienti di runtime) e importa un riepilogo delle vulnerabilità e della conformità alle policy per ciascuno.

#### Prerequisiti

È necessario un token di accesso personale Docker creato da un **proprietario** di un'organizzazione Docker **registrata a Docker Scout**. L'esportatore di metriche è una funzionalità a livello di organizzazione, quindi un account personale, o un'organizzazione non registrata a Docker Scout, non restituirà dati.

Crea il token dalle impostazioni del tuo account Docker in **Personal access tokens**, e prendi nota del **namespace dell'organizzazione** Docker, che ti servirà anche.

#### Mappature del Connector

1. Inserisci `https://api.scout.docker.com` nel campo **Percorso**.
2. Inserisci il tuo token di accesso personale Docker nel campo **Secret**.
3. Inserisci il namespace della tua **Organizzazione** Docker.
4. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati. I riscontri al di sotto della gravità selezionata non verranno importati.

DefectDojo crea un Record separato per ogni stream di Docker Scout e importa un riscontro per ogni livello di gravità relativo alle vulnerabilità che Docker Scout conteggia in quello stream, oltre a un riscontro per ogni immagine che non supera la tua policy di Docker Scout. L'API delle metriche di Docker Scout riporta conteggi aggregati anziché singole CVE, quindi questi riscontri riassumono la postura di uno stream. Apri lo stream in Docker Scout per il dettaglio per immagine e per CVE.

Per maggiori informazioni, consulta la [documentazione di Docker Scout](https://docs.docker.com/scout/).

## **Endor Labs**

Il connector Endor Labs utilizza l'API REST di Endor Labs per sincronizzare un intero **namespace** di Endor Labs. DefectDojo individua ogni **progetto** Endor come Record e ne importa i riscontri, riportando il verdetto di **raggiungibilità** di Endor, così puoi dare priorità alle vulnerabilità il cui codice interessato è effettivamente raggiungibile.

#### Prerequisiti

È necessaria una **chiave API** di Endor Labs (un identificativo della chiave più il relativo secret) e il **namespace** che vuoi sincronizzare. Crea la chiave nella piattaforma Endor Labs in **Settings \> Access \> API Keys**; la chiave necessita di accesso in lettura ai progetti e ai riscontri in quel namespace.

Il connector si autentica scambiando la chiave API e il secret per un token bearer di breve durata — il secret viene utilizzato solo per quello scambio e non viene mai memorizzato in chiaro.

#### Mappature del Connector

1. Inserisci `https://api.endorlabs.com` nel campo **Percorso**. Se il tuo tenant è ospitato in una regione diversa, utilizza invece l'URL di base dell'API di quella regione.
2. Inserisci il **Namespace** di Endor Labs da sincronizzare (ad esempio `your-org` o `your-org.team`).
3. Inserisci l'identificativo della **Chiave API**.
4. Inserisci l'**API Secret** associato alla chiave.
5. Facoltativamente, imposta **Attraversa i namespace figlio** su `true` per importare anche i riscontri dai namespace figlio del namespace configurato.
6. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati. I riscontri al di sotto della gravità selezionata non vengono importati.

DefectDojo crea un Record per ogni progetto Endor Labs nel namespace e ne importa i riscontri, mappando i livelli di gravità di Endor sulle gravità di DefectDojo, gli identificativi CVE/GHSA e il punteggio CVSS di ogni vulnerabilità, e i tag di raggiungibilità di Endor. Il verdetto di raggiungibilità (ad esempio *Reachable — vulnerable function is called* o *Unreachable*) viene mostrato come Impact del riscontro e come tag.

Per maggiori informazioni, consulta la **[documentazione dell'API REST di Endor Labs](https://docs.endorlabs.com/rest-api/)**.

## **Edgescan**

Il connector Edgescan utilizza l'API REST di Edgescan per importare le vulnerabilità aperte in tutto il tuo account Edgescan. DefectDojo enumera ogni **asset** di Edgescan e crea un Record per ciascuno, quindi importa le vulnerabilità aperte di quell'asset come riscontri — non è prevista alcuna configurazione per singolo asset.

#### Prerequisiti

È necessario un token API di Edgescan. Creane uno dal tuo account Edgescan in **Account settings \> API tokens**: inserisci un'etichetta, fai clic su **Create**, e copia il token generato (viene mostrato una sola volta). Consigliamo un account dedicato per il Connector, in modo che l'attività automatizzata sia facile da distinguere.

#### Mappature del Connector

1. Inserisci l'URL di Edgescan nel campo **Percorso** — `https://live.edgescan.com` per la piattaforma standard in hosting, oppure l'host del tuo tenant se diverso.
2. Inserisci il tuo token API di Edgescan nel campo **Secret**. Viene inviato come header `X-API-TOKEN`.
3. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Ogni asset di Edgescan diventa un Record, e ogni vulnerabilità aperta su quell'asset viene importata come riscontro. La gravità viene mappata dalla scala numerica di Edgescan (1–5) alla scala Info–Critica di DefectDojo, e vengono inclusi i riferimenti CVE, il CWE e un vettore CVSS v3 laddove Edgescan li fornisce.

## **Escape**

Il connector Escape utilizza l'API di [Escape](https://escape.tech) per importare i **riscontri di sicurezza delle API (DAST)**. DefectDojo enumera ogni organizzazione a cui il token può accedere e ogni applicazione al suo interno, crea un Record per ogni applicazione che ha una scansione, e importa i problemi dell'ultima scansione di quell'applicazione come riscontri — non è prevista alcuna configurazione per singola applicazione.

#### Prerequisiti

È necessaria una **chiave API** di Escape, creata nell'app Escape in **Settings → API keys**. La chiave viene inviata nell'header `Authorization: Key` e non viene mai registrata nei log.

#### Mappature del Connector

1. Lascia vuoto il campo **Percorso** per utilizzare `https://public.escape.tech/v2`, oppure inserisci esplicitamente l'host della tua API Escape.
2. Inserisci la chiave API di Escape nel campo **Secret**.
3. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

DefectDojo mappa ogni **applicazione** come Record e ogni **problema** della scansione come riscontro: la gravità deriva dalla valutazione di Escape (Critica/Alta/Media/Bassa), il CWE viene riportato, la categoria OWASP e il metodo HTTP diventano tag, l'URL interessato diventa l'endpoint, e vengono incluse le indicazioni di correzione. I riscontri vengono registrati come riscontri dinamici e deduplicati in base all'id del problema di Escape.

Per maggiori informazioni, consulta la [documentazione dell'API di Escape](https://docs.escape.tech/).

## **Fairwinds Insights**

Il connector Fairwinds Insights utilizza l'API REST di [Fairwinds Insights](https://insights.fairwinds.com) per importare i **riscontri di sicurezza Kubernetes** in tutta la tua organizzazione. DefectDojo enumera ogni **cluster** attivo e crea un Record per ciascuno, quindi importa gli **elementi di azione** di sicurezza di quel cluster \(da Polaris, Trivy, Kube\-bench, OPA e gli altri report di Insights\) come riscontri — non è prevista alcuna configurazione per singolo cluster.

#### Prerequisiti

È necessario il nome dell'**organizzazione** Fairwinds Insights e un **token API**. Crea il token nell'app Insights in **Organization Settings \> Tokens**; è sufficiente un token `read_only`. Il token ha un ambito limitato all'organizzazione ed è inviato come token bearer; non viene mai registrato nei log.

#### Mappature del Connector

1. Lascia vuoto il campo **Percorso** per utilizzare `https://insights.fairwinds.com`, oppure inserisci esplicitamente il tuo host Insights.
2. Inserisci il nome dell'**Organizzazione** Insights (lo slug mostrato nell'URL della tua dashboard).
3. Inserisci il token API di Insights nel campo **Secret**.
4. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

DefectDojo mappa ogni **cluster** attivo come Record e ogni **elemento di azione** di sicurezza come riscontro: la gravità deriva dal punteggio numerico di Fairwinds \(mappato su Info–Critica di DefectDojo\), il report di Fairwinds che ha generato l'elemento \(`polaris`, `trivy`, `kube-bench`, ...\) diventa un tag dello strumento, vengono inclusi la risorsa Kubernetes interessata e l'immagine container, e vengono estratti eventuali identificativi CVE. I riscontri vengono registrati come riscontri statici e deduplicati in base all'id dell'elemento di azione di Fairwinds.

Per maggiori informazioni, consulta la [documentazione dell'API di Fairwinds Insights](https://insights.docs.fairwinds.com/technical-details/api/).

## **Fortify**

Il connector Fortify importa i risultati SAST/DAST da Fortify (OpenText/Micro Focus), coprendo entrambe le edizioni che condividono la piattaforma: **SSC** (Software Security Center, self-hosted) e **Fortify on Demand (FoD)** (SaaS). Sincronizza l'intero account: DefectDojo individua ogni applicazione (versione del progetto SSC / release FoD) e crea un Record per ciascuna, quindi importa i problemi di quell'applicazione come riscontri.

#### Prerequisiti

- **SSC**: un **FortifyToken** — creane uno nell'interfaccia SSC in **Administration → Token Management** (un CIToken/UnifiedLoginToken).
- **FoD**: una **chiave API OAuth2** — un Client ID e Client Secret da **Settings → API** (con l'ambito `api-tenant`).

Il token e il secret OAuth non vengono mai registrati nei log.

#### Mappature del Connector

1. Inserisci l'URL di base di Fortify nel campo **Percorso**: per SSC l'host del tuo server (il connector aggiunge `/ssc/api/v1`); per FoD l'host API della tua regione, ad esempio `https://api.ams.fortify.com`.
2. Imposta **Edizione** su `SSC` o `FoD`.
3. Per **FoD**, inserisci il **Client ID** OAuth; lascialo vuoto per SSC.
4. In **Token / Client Secret**, inserisci il FortifyToken SSC oppure il client secret OAuth di FoD.
5. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

DefectDojo mappa ogni **applicazione** Fortify come Record e ogni **problema** come riscontro: la gravità deriva dalla valutazione **friority** propria di Fortify (Critica/Alta/Media/Bassa), il titolo combina la categoria del problema con il suo file e la riga, e vengono riportati il percorso del file, la riga, il kingdom, l'analyzer e il tipo di motore. I problemi provenienti da motori di analisi statica (SCA) vengono registrati come riscontri statici e i problemi WebInspect (DAST) come riscontri dinamici; i problemi soppressi, rimossi e nascosti vengono saltati, i problemi verificati come "Not an Issue" sono contrassegnati come Falso positivo, e i problemi "Exploitable"/revisionati sono contrassegnati come Verificato.

Per maggiori informazioni, consulta la documentazione API di [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) e [Fortify on Demand](https://api.ams.fortify.com/swagger/ui).

## **GitGuardian**

Il connector GitGuardian utilizza l'API REST di GitGuardian per importare gli **incidenti relativi ai secret** — credenziali esposte che GitGuardian ha rilevato nelle tue fonti monitorate. DefectDojo crea un Record per ogni fonte monitorata (repository o perimeter) che al momento presenta incidenti aperti, e importa ogni incidente aperto come riscontro.

Per la tua sicurezza, il connector importa solo i **metadati** dell'incidente — il detector, la gravità, la validità, lo stato e un link che rimanda a GitGuardian. Il valore del secret esposto non viene mai recuperato o memorizzato da DefectDojo; segui il link in ogni riscontro per esaminare le posizioni interessate in GitGuardian.

#### Prerequisiti

È necessaria una chiave API di GitGuardian. Consigliamo un **Service Account token** (anziché un token di accesso personale) in modo che l'attività automatizzata sia facile da distinguere. Creala in **API** nella dashboard di GitGuardian e concedi questi ambiti in lettura:

* `incidents:read`
* `sources:read`

#### Mappature del Connector

1. Inserisci l'URL dell'API di GitGuardian nel campo **Percorso**: `https://api.gitguardian.com` per la piattaforma SaaS, oppure l'URL dell'API della tua istanza self-hosted.
2. Inserisci la chiave API nel campo **Secret**.

Vengono importati solo gli incidenti **aperti** (stato `TRIGGERED` o `ASSIGNED`); gli incidenti che risolvi o ignori in GitGuardian vengono automaticamente mitigati in DefectDojo alla sincronizzazione successiva. Un secret confermato attivo (validità *valid*) viene importato come riscontro Verificato.

## **GitHub**

Il connector GitHub è un **Asset Connector**: enumera i repository a cui il tuo token può accedere e crea un Asset di DefectDojo per ciascuno, raggruppati in Organizzazioni in base al proprietario GitHub (organizzazione o utente). Non viene importato alcun riscontro.

**Nota:** questo connector importa solo l'**inventario** dei tuoi repository. Per importare gli avvisi di sicurezza di GitHub — code scanning, Dependabot e secret scanning — come riscontri, utilizza il connector separato **GitHub Advanced Security** riportato di seguito. I due sono indipendenti e possono essere eseguiti insieme.

#### Prerequisiti

Il connector si autentica con un **token di accesso personale** di GitHub e legge solo i **metadati** del repository (nome, descrizione, URL e proprietario) — non accede al tuo codice, ai problemi o agli avvisi di sicurezza. Importa ogni repository di cui l'account del token è proprietario, collaboratore, o di cui è membro dell'organizzazione, quindi verifica che l'account del token possa vedere i repository che vuoi replicare. Consigliamo un account di servizio dedicato.

Il token necessita solo di accesso in sola lettura ai metadati del repository:

- Un token *fine-grained* necessita di **Repository permissions → Metadata: Read-only**, concesso ai repository (o all'intera organizzazione) che vuoi importare.
- Un token *classic* necessita dell'ambito **`repo`** per includere i repository privati (usa **`public_repo`** se ti servono solo quelli pubblici), oltre a **`read:org`** affinché vengano risolti i repository di proprietà dell'organizzazione.

È supportato solo GitHub.com (inclusa GitHub Enterprise Cloud). GitHub Enterprise **Server** non è al momento supportato da questo connector.

#### Mappature del Connector

1. Inserisci `https://api.github.com` nel campo **Percorso**.
2. Inserisci il token di accesso personale nel campo **Secret**.

Non è necessario inserire alcun elenco di organizzazioni o repository — DefectDojo importa ogni repository che il token può vedere. Ogni repository diventa un Record denominato come il repository, raggruppato in base al **proprietario** GitHub (organizzazione o utente). Se un repository viene successivamente eliminato, o il token perde l'accesso ad esso, il suo Record mappato viene contrassegnato come `MISSING` alla successiva Sincronizzazione invece di essere rimosso — DefectDojo non elimina mai silenziosamente un Prodotto.

## **GitHub Advanced Security**

Il connector GitHub Advanced Security importa gli avvisi di **code scanning**, **Dependabot** e **secret scanning** da GitHub, come tre tipi di riscontro separati (`GitHub:CodeScanning`, `GitHub:Dependabot` e `GitHub:SecretScanning`). DefectDojo individua ogni repository non\-archiviato nell'organizzazione configurata e crea un Record per ciascuno.

#### Prerequisiti

Le funzionalità di GitHub Advanced Security devono essere abilitate per i repository che vuoi importare. Il connector si autentica con un **token di accesso personale** di GitHub:

1. Su GitHub, apri **Settings \> Developer settings \> Personal access tokens** e crea un token di proprietà (o con accesso a) dell'organizzazione target.
2. Concedigli l'accesso in lettura agli avvisi di sicurezza: un token *fine\-grained* necessita dell'accesso **Read\-only** a **Code scanning alerts**, **Dependabot alerts** e **Secret scanning alerts** sui repository dell'organizzazione; un token *classic* necessita degli ambiti **`repo`** e **`security_events`**.
3. Verifica che il proprietario del token possa vedere i repository che intendi importare — il connector vede solo i repository a cui il token può accedere.

#### Mappature del Connector

1. Inserisci `https://api.github.com` nel campo **Percorso**. Per GitHub Enterprise Server, usa `https://<your-host>/api/v3`.
2. Inserisci il login dell'organizzazione nel campo **Organizzazione**.
3. Inserisci il token di accesso personale nel campo **Secret**.
4. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Ogni repository non\-archiviato diventa un Record, interrogato sulle tre famiglie di avvisi per individuare gli avvisi aperti. Una famiglia di avvisi non abilitata per un repository viene saltata invece di essere segnalata come risolta, quindi le funzionalità disabilitate non causano chiusure errate.

## **GitLab**

Il connector GitLab è un **Asset Connector**: enumera ogni progetto (repository) a cui il tuo token può accedere e crea un Asset di DefectDojo per ciascuno, raggruppati in Organizzazioni in base al namespace GitLab (gruppo o utente). Non viene importato alcun riscontro.

#### Prerequisiti

È necessario un Token di accesso personale con l'ambito **read_api**. Consigliamo di creare il token da un account di servizio dedicato; il connector elenca i progetti di cui quell'account è membro.

#### Mappature del Connector

1. Inserisci l'URL di GitLab nel campo **Percorso**: `https://gitlab.com`, oppure l'URL di base della tua istanza self-hosted.
2. Inserisci il Token di accesso personale nel campo **Secret**.

Ogni progetto diventa un Record denominato come il progetto, raggruppato in base al suo **namespace**. I progetti in attesa di eliminazione su GitLab (eliminati da un utente, ma non ancora rimossi definitivamente dal job in background di GitLab) vengono esclusi automaticamente, quindi l'eliminazione di un progetto contrassegna il suo Record come `MISSING` alla successiva Sincronizzazione invece di lasciare un asset fantasma rinominato.

## **Google Cloud Security Command Center**

Il connector Google Cloud SCC utilizza l'API REST v2 di Security Command Center per importare i riscontri di sicurezza attivi dalla tua organizzazione, cartella o progetto Google Cloud. DefectDojo crea un Record per ogni **progetto** Google Cloud che presenta riscontri aperti.

#### Prerequisiti

Security Command Center deve essere **attivato** sulla tua organizzazione (il livello Standard è gratuito). Ti servirà quindi un account di servizio in grado di elencare i riscontri, e una chiave JSON per esso:

1. Su Google Cloud, crea un account di servizio — se ne consiglia uno dedicato per DefectDojo.
2. Assegnagli il ruolo **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) all'ambito da cui vuoi importare (organizzazione, cartella o progetto).
3. Crea una **chiave JSON** per l'account di servizio e scaricala.

#### Mappature del Connector

1. Lascia il campo **Percorso** al valore predefinito `https://securitycenter.googleapis.com`, a meno che tu non utilizzi un endpoint non standard.
2. Nel campo **Risorsa principale**, inserisci l'ambito da cui importare: `organizations/{id}`, `folders/{id}`, oppure `projects/{id}`.
3. Incolla l'intero contenuto del file della **chiave JSON** dell'account di servizio nel campo **Chiave dell'account di servizio**.
4. Facoltativamente, imposta una **Gravità minima** per limitare quali riscontri vengono importati.

Vengono importati solo i riscontri `ACTIVE` non silenziati, quindi i riscontri che disattivi o silenzi in SCC vengono automaticamente mitigati in DefectDojo alla sincronizzazione successiva. Il progetto GCP interessato da ogni riscontro diventa il suo Record.

## **Group-IB ASM**

Il connettore Group-IB ASM (Attack Surface Management) utilizza l'API REST di Group-IB ASM per importare in DefectDojo i **problemi** (riscontri) della superficie di attacco esterna. DefectDojo rileva ogni **azienda/tenant** Group-IB come Record distinto e importa i problemi di tale azienda in modo pianificato e incrementale. L'asset a cui è collegato ciascun problema (un dominio, un indirizzo IP o un URL) viene associato al riscontro risultante come **Endpoint**.

#### Prerequisiti

Sono necessari il login di Group-IB ASM e una chiave API. Si consiglia di creare un account di servizio dedicato per DefectDojo, in modo da distinguere chiaramente l'attività automatizzata dalle azioni manuali del team.

Per generare una chiave API:

1. Aprire Group-IB Attack Surface Management, fare clic su **Help** nell'angolo in basso a sinistra e selezionare **API**.
2. Fare clic su **Generate API Key** (in alto a destra, sotto il nome utente).
3. Inserire la password SSO, fare clic su **Next**, quindi fare clic su **Copy token**.
4. Conservare la chiave in un secret manager e pianificarne la rotazione periodica.

#### Mappature del connettore

Group-IB ASM utilizza l'autenticazione HTTP Basic Auth, in cui il nome utente è il login ASM e la password è la chiave API. **Entrambi i valori sono obbligatori**: la sola chiave API non è sufficiente.

1. Inserire `https://asm.group-ib.com` nel campo **Location**. Questo valore è identico per tutti i tenant Group-IB ASM.
2. Inserire il login ASM (di norma un indirizzo email) nel campo **Username**.
3. Inserire la chiave API nel campo **API Key** (Secret).
4. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati. I riscontri con gravità inferiore a quella selezionata non vengono importati.

DefectDojo mappa ogni **azienda** Group-IB come Record distinto, utilizzando l'ID dell'azienda come identificativo. Alla prima Sincronizzazione, DefectDojo compila retroattivamente la cronologia recente dei problemi; le Sincronizzazioni successive sono incrementali e importano solo i problemi modificati dall'ultima Sincronizzazione (in base al timestamp `lastSeen` più recente di ciascun problema).

#### Ambito su una singola azienda (opzionale)

Per impostazione predefinita, il connettore rileva automaticamente le aziende disponibili per le credenziali API in uso (tramite l'endpoint ASM `clients`) e crea un Record per ciascuna azienda. Questa è la configurazione consigliata e non richiede alcuna impostazione aggiuntiva.

Se l'endpoint `clients` non è disponibile per il proprio tenant — ad esempio quando è limitato agli account partner/MSP — il connettore può essere limitato a una singola azienda specificando il relativo **ID azienda** nel campo specifico del tool `company_id` nella configurazione del connettore. Quando `company_id` è impostato, DefectDojo utilizza direttamente quell'azienda invece di enumerarle tutte. Lasciare il campo non impostato per utilizzare il rilevamento automatico.

Per ulteriori informazioni, consultare il manuale dell'API REST di Group-IB ASM (disponibile all'interno del prodotto tramite **Help → API**).

## **HackerOne**

Il connettore HackerOne utilizza l'API REST di HackerOne per importare i report dal programma di bug bounty o di vulnerability disclosure dell'organizzazione. DefectDojo crea un Record per ogni programma accessibile con il token e ne importa i report come riscontri.

#### Prerequisiti

Il connettore utilizza l'API **customer** di HackerOne, che richiede un **organization API token** — un token personale proveniente dalle impostazioni utente funziona solo con l'API hacker e non consente l'autenticazione qui.

1. In HackerOne, accedere a **Organization Settings > API Tokens**.
2. Creare un token e annotare sia l'**identifier** sia il valore del **token**. È sufficiente l'accesso in sola lettura al programma.

#### Mappature del connettore

1. Inserire `https://api.hackerone.com` nel campo **Location**.
2. Inserire l'**identifier** del token nel campo **API Token Identifier**.
3. Inserire il valore del token nel campo **API Token**.
4. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati.

Ogni programma diventa un Record e i relativi report vengono importati come riscontri mantenendo la valutazione di gravità originale di HackerOne.

## **Harbor**

Il connettore Harbor utilizza l'API REST Harbor v2.0 per importare le vulnerabilità delle immagini container dell'intero registry. DefectDojo enumera ogni **progetto** Harbor e crea un Record per ciascuno, quindi analizza i repository e gli artifact del progetto e importa le vulnerabilità di ogni artifact **sottoposto a scansione** — riportando l'immagine (repository + tag/digest) come contesto del riscontro. Non è prevista alcuna configurazione per singola immagine.

#### Prerequisiti

È necessario un account Harbor (oppure un **robot account**) con accesso in pull/lettura ai progetti da importare. Si consiglia un robot account dedicato: in Harbor, aprire un progetto (oppure **Administration \> Robot Accounts** per un robot di sistema), creare un robot con il permesso **pull** su repository e artifact, quindi copiarne nome completo e secret. Per impostazione predefinita i nomi dei robot iniziano con `robot$`, ma il prefisso è configurabile per ogni istanza Harbor (alcune usano `robot_`) — copiare il nome esattamente come mostrato da Harbor. Funziona anche una normale coppia nome utente/password.

#### Mappature del connettore

1. Inserire l'URL di Harbor nel campo **Location** — ad esempio `https://harbor.example.com`. DefectDojo aggiunge automaticamente il percorso API `/api/v2.0`.
2. Inserire il nome utente Harbor, oppure il nome di un robot account esattamente come mostrato da Harbor (per impostazione predefinita `robot$<name>`), nel campo **Username**.
3. Inserire la password o il secret del robot account nel campo **Secret**. Viene inviato tramite autenticazione HTTP Basic.
4. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati.

Ogni progetto Harbor diventa un Record. Per ogni artifact con una scansione completata, le relative vulnerabilità vengono importate come riscontri; dove Harbor le fornisce, sono incluse anche il pacchetto/versione interessati, una gravità derivata da CVSS, il CVE, il CWE e una remediation (versione corretta). Vengono importati solo gli artifact sottoposti a scansione — avviare una scansione in Harbor per le immagini non ancora scansionate.

## **Have I Been Pwned**

Il connettore Have I Been Pwned (HIBP) utilizza l'API REST di HIBP per segnalare quali account sui domini di proprietà dell'organizzazione sono comparsi in data breach noti. DefectDojo rileva ogni dominio verificato con HIBP e importa un riscontro per ogni breach che interessa tale dominio.

#### Prerequisiti

È necessaria una chiave API di Have I Been Pwned con ricerca sui domini, disponibile a partire dal livello di abbonamento **Core**. La chiave può essere ottenuta dal proprio [account Have I Been Pwned](https://haveibeenpwned.com/API/Key).

È inoltre necessario **verificare almeno un dominio** sul proprio account HIBP prima che siano disponibili dati sui breach. HIBP consente di verificare un dominio tramite record DNS TXT, meta tag, caricamento di un file o email, nella sezione **Domain search** del proprio account. Finché un dominio non è verificato, il connettore non rileva alcun dominio e non importa alcun riscontro.

#### Mappature del connettore

1. Inserire `https://haveibeenpwned.com` nel campo **Location**.
2. Inserire la chiave API nel campo **Secret**.
3. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati. I riscontri con gravità inferiore a quella selezionata non verranno importati.

DefectDojo crea un Record distinto per ogni dominio verificato con HIBP e importa un riscontro per ogni breach che interessa gli account su tale dominio. La gravità di ciascun riscontro riflette il tipo di dati esposti dal breach e la relativa descrizione elenca gli account interessati sul dominio, in modo che il team possa intervenire.

Per ulteriori informazioni, consultare la [documentazione API di Have I Been Pwned](https://haveibeenpwned.com/API/v3).

## **HCL AppScan**

Il connettore HCL AppScan utilizza l'API REST AppScan v4 per importare i problemi da **AppScan on Cloud (ASoC)** o da un'istanza self-hosted di **AppScan 360°** (entrambi condividono la stessa API). Sincronizza l'intero account: DefectDojo rileva ogni applicazione e crea un Record per ciascuna, quindi importa come riscontri i problemi di tale applicazione (DAST, SAST e IAST).

#### Prerequisiti

È necessaria una **chiave API** di AppScan — un Key ID e un Key Secret generati nelle impostazioni dell'account AppScan (API Key). Il connettore li scambia con un token di sessione di breve durata a ogni esecuzione; Key ID, Key Secret e token non vengono mai registrati nei log.

#### Mappature del connettore

1. Inserire l'URL della console AppScan nel campo **Location**: per ASoC utilizzare `https://cloud.appscan.com` (oppure `https://eu.cloud.appscan.com` per la regione UE); per AppScan 360° utilizzare l'host della propria istanza.
2. Impostare **Provider** su `ASOC` per AppScan on Cloud, oppure su `A360` per un'istanza self-hosted di AppScan 360°.
3. Inserire **API Key ID** e **API Key Secret**.
4. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati.

DefectDojo mappa ogni **applicazione** AppScan su un Record (VEP) e ogni **problema** su un riscontro: il titolo è il tipo di problema con dominio / entità / cause-id / URL / percorso aggiunti in coda; la gravità mappa Informational su Info (Bassa/Media/Alta/Critica restano invariate); vengono riportati il CWE, una descrizione etichettata, la remediation e l'advisory, e l'endpoint host/porta. I problemi rilevati tramite analisi statica vengono registrati come riscontri statici e i problemi dinamici/interattivi come riscontri dinamici; i problemi aperti sono Attivo e quelli risolti/superati sono Mitigato.

Per ulteriori informazioni, consultare la [documentazione API REST di AppScan](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html).

## **Intigriti**

Il connettore Intigriti utilizza l'API esterna per aziende di Intigriti per importare in DefectDojo le **segnalazioni** di bug bounty / pentest. Sincronizza l'intero account aziendale: DefectDojo rileva ogni programma accessibile con il token e crea un Record per ciascuno, quindi importa le segnalazioni di tale programma come riscontri.

#### Prerequisiti

È necessario un **company API token** di Intigriti. Nel portale aziendale di Intigriti, in **Company Settings > API** (ambito `company_external_api`), generare un token di accesso con accesso in lettura ai propri programmi e segnalazioni. Si consiglia un token dedicato per DefectDojo. Il token viene inviato come Bearer token e non viene mai registrato nei log.

#### Mappature del connettore

1. Inserire l'URL base dell'API esterna per aziende di Intigriti nel campo **Location**: `https://api.intigriti.com/external/company`. L'URL deve essere HTTPS.
2. Inserire il company API token nel campo **Secret**.
3. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati.

DefectDojo mappa ogni **programma** Intigriti su un Record e ogni **segnalazione** su un riscontro, identificato in base al codice della segnalazione. La gravità del riscontro segue la valutazione di Intigriti (Exceptional/Critical → Critica, quindi Alta/Media/Bassa, altrimenti Info), e lo stato del ciclo di vita della segnalazione viene mappato sullo stato del riscontro: le segnalazioni aperte/in triage sono Attivo, quelle accettate sono Verificato e quelle chiuse diventano Mitigato, Duplicato, Fuori ambito, Falso positivo o Rischio accettato a seconda del motivo di chiusura. La descrizione del riscontro riporta il tipo di vulnerabilità del report, l'asset interessato, la proof of concept e le risposte del ricercatore.

Per ulteriori informazioni, consultare la [documentazione API di Intigriti](https://kb.intigriti.com/en/articles/6117846-intigriti-api).

## **Intruder**

Il connettore Intruder utilizza l'[API REST di Intruder](https://developers.intruder.io/) per importare in DefectDojo la postura dell'intero account. Ogni **target** Intruder viene rilevato come Record (Prodotto); ogni **occorrenza** di un problema su un target diventa un Riscontro.

#### Mappature del connettore

1. Lasciare il campo **Location** impostato su `https://api.intruder.io/` (il server API predefinito di Intruder).
2. Inserire un **API access token** di Intruder nel campo **Secret**.

Generare un token di accesso in Intruder in **My account > API Access Tokens** (è necessaria la password dell'account per crearlo, e il token viene mostrato una sola volta). Per maggiori dettagli, consultare la [documentazione API di Intruder](https://developers.intruder.io/docs/creating-an-access-token).

I riscontri vengono derivati per ogni occorrenza: la gravità deriva dalla gravità del problema, i CVE e il CVSS dall'occorrenza, la posizione dal target/porta, e un'occorrenza posta in snooze viene importata come riscontro inattivo (Falso positivo o Rischio accettato).

## **IriusRisk**

Il connettore IriusRisk utilizza un token API per importare i dati di threat modeling dalla propria istanza IriusRisk.

#### Prerequisiti

È necessario un token API del proprio account IriusRisk. Si consiglia di creare un account di servizio dedicato per DefectDojo, in modo da distinguere chiaramente l'attività automatizzata dalle azioni manuali del team.

Per generare un token API in IriusRisk:

1. Accedere alla propria istanza IriusRisk.
2. Accedere a **User Profile** nel menu in alto a destra.
3. Selezionare **API Token** e generare un nuovo token.

Per ulteriori informazioni, consultare la [documentazione API di IriusRisk](https://support.iriusrisk.com/hc/en-us/categories/360001148511).

#### Mappature del connettore

1. Inserire l'URL della propria istanza IriusRisk nel campo **Location URL**. Per le istanze cloud, in genere è `https://{your-subdomain}.iriusrisk.com`. Per le installazioni on-premise, utilizzare l'URL base della propria istanza.
2. Inserire il proprio **API Token** nel campo **Secret**.
3. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati. I riscontri con gravità inferiore a quella selezionata non verranno importati.

## **JFrog Xray**

Il connettore JFrog Xray utilizza l'API REST di JFrog Xray per recuperare i dati sulle vulnerabilità dai repository Artifactory. DefectDojo rileva tutti i repository presenti nell'istanza JFrog e genera report sulle vulnerabilità tramite Xray, importando i riscontri in modo pianificato.

#### Prerequisiti

È necessario un token API con accesso sia alle API di Artifactory sia a quelle di Xray. Si consiglia di creare un account di servizio dedicato per DefectDojo. L'account richiede:

* Accesso in lettura ai repository Artifactory
* Il permesso di generare e visualizzare i report sulle vulnerabilità di Xray (permesso `Apply on Watches` in Xray, o equivalente)

#### Mappature del connettore

1. Inserire l'URL base della propria istanza JFrog nel campo **Location**. Deve essere l'URL radice dell'istanza JFrog, ad esempio `https://your-instance.jfrog.io`. Non includere un percorso finale — DefectDojo costruirà automaticamente i percorsi API appropriati.
2. Inserire un **Reference Token** valido nel campo **Secret**. I token possono essere generati in **User Management \> Access Tokens** nell'interfaccia di JFrog Platform.
È necessario generare un **Reference Token** e utilizzare tale valore.

Ambiti del token richiesti per JFrog Xray:

- **All Services**, poiché DefectDojo necessita di accesso sia ai servizi XRay sia a quelli Artifactory
- Come minimo, **Manage Reports + Manage Resources**.

Per impostazione predefinita, DefectDojo mappa ogni **repository** Artifactory come Record distinto. Ogni Sincronizzazione genera un report completo sulle vulnerabilità per repository tramite Xray, pertanto gli stati dei riscontri in DefectDojo riflettono sempre lo stato attuale del repository.

#### Repository Filter (opzionale)

Per impostazione predefinita il connettore rileva **ogni** repository presente nell'istanza JFrog. Nelle istanze con un numero elevato di repository — molti dei quali potrebbero non essere rilevanti ai fini della revisione della sicurezza — il rilevamento può essere limitato tramite il campo facoltativo **Repository Filter**, in **Import Filters** nel modulo del connettore.

Il filtro viene applicato durante il rilevamento, **prima che venga svolto qualsiasi lavoro per singolo repository**. Un repository escluso dal filtro non comporta alcun costo: non viene generato alcun report Xray per esso e, in modalità artifact, non viene enumerato nessuno dei suoi artifact di primo livello. Questo lo rende il modo più efficace per ridurre sia i tempi di Sincronizzazione sia il carico che DefectDojo impone sull'istanza JFrog — più di qualsiasi impostazione applicata più avanti nella Sincronizzazione. È particolarmente consigliato insieme a **Artifact\-Level Records** nelle istanze di grandi dimensioni.

**Sintassi:** un elenco di chiavi di repository separate da virgola. Ogni voce può utilizzare i caratteri jolly `*`:

* Una voce contenente `*` viene interpretata come pattern — `releases-*` corrisponde a ogni chiave di repository che inizia con `releases-`, e `*docker-pr-local*` corrisponde a qualsiasi chiave contenente `docker-pr-local`. Un `*` corrisponde a qualsiasi sequenza di caratteri, incluso `/`.
* Una voce senza `*` deve corrispondere **esattamente** a una chiave di repository.
* Un repository viene rilevato se corrisponde a **una qualsiasi** voce dell'elenco. Gli spazi intorno alle virgole vengono ignorati.

```
releases-*, snapshots
```

L'esempio precedente rileva ogni repository la cui chiave inizia con `releases-`, oltre al singolo repository denominato esattamente `snapshots`.

Note:

* Il filtro è una **allow\-list** — una corrispondenza seleziona un repository. Non esiste una sintassi di esclusione o negazione, quindi non è possibile esprimere direttamente "tutto tranne X".
* La corrispondenza è **case\-sensitive**, sia per le voci esatte sia per i caratteri jolly. `*` è l'unico carattere jolly supportato; `?` e gli intervalli di caratteri non sono supportati.
* **Lasciare vuoto per rilevare ogni repository.** Un valore composto solo da spazi o virgole viene considerato vuoto.
* Un filtro che non corrisponde a nulla semplicemente non rileva nulla — non viene generato alcun errore. Se una Sincronizzazione non rileva inaspettatamente alcun repository, controllare nel log del connettore la voce `repository filter scoped discovery`, che indica quanti dei repository totali corrispondevano.
* Il campo può essere modificato dopo la creazione della connessione.

**Modificare il filtro in seguito:** i repository che un filtro appena ristretto ora esclude non vengono più rilevati, e i loro Record esistenti seguono il normale ciclo di vita previsto per i prodotti che lo strumento non segnala più — i Record **mappati** vengono contrassegnati come `MISSING` alla Sincronizzazione successiva, mentre i Record `NEW` non mappati vengono rimossi. I riscontri già importati in DefectDojo non vengono eliminati; il filtro governa solo il rilevamento.

#### Artifact-Level Records

L'opzione **Artifact-Level Records** modifica il rilevamento portandolo un livello sotto il repository: ogni voce di primo livello sotto la radice di un repository (per i repository Docker, ogni immagine; per i repository generici, ogni file o cartella di primo livello) diventa un Record a sé stante. Ogni Sincronizzazione continua a generare un unico report Xray per repository — DefectDojo attribuisce ciascuna vulnerabilità agli artifact che interessa, quindi il carico sull'istanza JFrog non aumenta.

> **Verificare in quale modalità ci si trova prima della prima Sincronizzazione.** Artifact\-Level Records è **attivo per impostazione predefinita nelle nuove installazioni**. Le installazioni precedenti all'introduzione della funzionalità mantengono il layout esistente a livello di repository, quindi per queste l'opzione è disattivata finché qualcuno non la attiva. In entrambi i casi l'opzione può essere modificata in qualsiasi momento — vedere *Passaggio a una connessione esistente* più avanti.

Con Artifact-Level Records attivato:

* I repository restano come Record e diventano **asset padre**: non contengono riscontri propri, ma quando la funzionalità Asset Hierarchy è attivata, DefectDojo collega automaticamente ogni asset di tipo artifact al proprio asset di tipo repository con una relazione `parent`. Gli asset possono quindi essere filtrati per padre/figlio e i riscontri risalgono la gerarchia.
* Una vulnerabilità che interessa più artifact viene importata in ciascun asset artifact interessato, in modo che ogni asset mostri l'insieme completo dei riscontri che lo riguardano.
* I riscontri sono limitati alla **build più recente** di ciascun artifact, quindi i riscontri di un artifact descrivono la sua build attuale invece di accumulare i risultati di ogni build mai scansionata da Xray.
* Le relazioni gerarchiche create dal connettore non sovrascrivono mai le relazioni create manualmente. Se un asset ha già un padre assegnato manualmente, il connettore lo lascia invariato.
* Il token necessita inoltre di accesso in lettura all'API di storage di Artifactory (inclusa negli ambiti sopra indicati).

**Passaggio di una connessione esistente ad Artifact-Level Records:** l'opzione può essere modificata in qualsiasi momento. Alla prima Sincronizzazione successiva, compaiono nuovi Record di tipo artifact da mappare — attivare **Auto Map** sulla connessione quando si cambia l'opzione, in modo che i riscontri si spostino senza interruzioni. Gli asset a livello di repository smettono di ricevere riscontri e i riscontri precedentemente importati vengono chiusi alla Sincronizzazione successiva (gli stessi riscontri vengono reimportati sotto i nuovi asset artifact, con uno stato aggiornato); le note e la cronologia dei vecchi riscontri a livello di repository restano sull'asset repository. Tornare indietro inverte questo comportamento: i Record a livello di repository riprendono a contenere riscontri (i riscontri precedentemente chiusi si riaprono quando tornano a corrispondere), e i Record di tipo artifact vengono contrassegnati come MISSING — i relativi asset e riscontri vengono mantenuti ma smettono di aggiornarsi, così da poterli archiviare quando più conviene.

Per ulteriori informazioni, consultare la [documentazione API REST di JFrog Xray](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis).

## **Jira Service Management Assets**

Il connettore JSM Assets è un **Asset Connector**: enumera gli oggetti presenti nel workspace Jira Service Management Assets (in precedenza Insight) e crea un Asset DefectDojo per ciascun oggetto, raggruppato in Organizzazioni in base allo schema dell'oggetto. Non viene importato alcun riscontro.

#### Prerequisiti

* Assets richiede un piano **Jira Service Management Premium o Enterprise**. Nei piani Free o Standard, l'API Assets risponde con `403 "Access to Assets API was denied"`, anche se il resto del sito funziona normalmente.
* L'account Atlassian utilizzato deve disporre di **Jira Service Management product access** (una licenza agente) sul sito — il solo accesso al sito non è sufficiente.
* Creare un token API Atlassian classico su [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Si consiglia un account di servizio dedicato.

#### Mappature del connettore

1. Inserire l'URL del proprio sito Atlassian nel campo **Location**: `https://{your-site}.atlassian.net`.
2. Inserire l'email dell'account Atlassian a cui appartiene il token nel campo **Email**.
3. Inserire il token API nel campo **Secret**.

Ogni oggetto Assets diventa un Record denominato in base all'etichetta dell'oggetto, raggruppato per il relativo **object schema**.

## **Kubescape**

Il connettore Kubescape legge i risultati sulla postura Kubernetes (misconfigurazioni) prodotti dall'[operatore Kubescape](https://kubescape.io/docs/install-operator/) direttamente dall'API Kubernetes del cluster — senza che sia necessario alcun account SaaS ARMO. Legge gli oggetti `WorkloadConfigurationScan` esposti dall'API aggregata di storage in-cluster dell'operatore (`spdx.softwarecomposition.kubescape.io/v1beta1`). Ogni **namespace** Kubernetes con risultati sulla postura viene mappato su un Record (Prodotto); ogni controllo non superato su un workload diventa un Riscontro.

#### Prerequisiti

- L'operatore Kubescape deve essere installato nel cluster di destinazione con la scansione delle configurazioni attivata (vedere [Installazione nel cluster](https://kubescape.io/docs/install-operator/)). Verificare che i risultati esistano con `kubectl get workloadconfigurationscans -A`.
- Un **kubeconfig** con accesso in lettura al gruppo API `spdx.softwarecomposition.kubescape.io` (list/get su `workloadconfigurationscans`) per il cluster di destinazione.

#### Mappature del connettore

1. Inserire l'URL del server API del cluster (o un identificativo descrittivo del cluster) nel campo **Location**.
2. Incollare il **kubeconfig** del cluster di destinazione nel campo `kubeconfig`. Facoltativamente, impostare `kube_context` per selezionare un contesto al suo interno, e `cluster_name` per etichettare i Prodotti rilevati.
3. Ogni namespace con risultati sulla postura viene rilevato come Record; mappare quelli che si desidera importare nei Prodotti DefectDojo.

I riscontri vengono derivati per ogni controllo non superato: il nome del controllo e il workload identificano il Riscontro, la gravità deriva dal fattore di punteggio del controllo, l'ID del controllo diventa l'ID della vulnerabilità, e ogni Riscontro rimanda al proprio riferimento del controllo su `https://hub.armosec.io/docs/`.

## **Mend**

Il connettore Mend (in precedenza **WhiteSource**) utilizza l'API Mend per importare i riscontri di sicurezza dall'organizzazione Mend. DefectDojo crea un Record per ogni **progetto** Mend.

#### Prerequisiti

È necessario un utente (di servizio) Mend con una **User Key** (un token di accesso personale) e l'**Organization UUID** Mend. Si consiglia un account di servizio dedicato, in modo da distinguere facilmente l'attività automatizzata dalle azioni manuali del team. L'Organization UUID si trova nell'app Mend in **Administration > Organization UUID**.

#### Mappature del connettore

1. Inserire l'URL dell'API Mend nel campo **Location**. Questo URL è **specifico per regione** — utilizzare l'URL base dell'API della regione in cui è ospitata l'organizzazione Mend.
2. Inserire l'email di accesso dell'utente Mend nel campo **Email**.
3. Inserire l'**Organization UUID** Mend nel campo **Organization UUID**.
4. Inserire la **User Key** Mend nel campo **User Key**.
5. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati.

## **Lacework / FortiCNAPP**

Il connettore Lacework / FortiCNAPP utilizza l'API Lacework v2 per importare le **vulnerabilità di host e container** dell'intero account Lacework.

#### Prerequisiti

È necessaria una **chiave API** Lacework — un API key id e un secret, creati nella console Lacework in **Settings → API keys**. Il connettore li scambia con un token di accesso di breve durata a ogni sincronizzazione; key id, secret e token non vengono mai registrati nei log.

#### Mappature del connettore

1. Inserire l'URL dell'account Lacework nel campo **Location** — ad esempio `https://YOUR-ACCOUNT.lacework.net` (è accettato anche un semplice nome account).
2. Inserire **API Key ID** e **API Secret**.
3. Facoltativamente, impostare una **Minimum Severity** per limitare quali riscontri vengono importati.

DefectDojo mappa l'**account** Lacework su un Record (l'ambito dell'intero account). Ogni vulnerabilità di **container** e di **host** diventa un riscontro: la gravità deriva dalla valutazione originale di Lacework, il pacchetto e la versione interessati diventano il componente, la versione con la correzione diventa la mitigazione, e l'immagine/host interessato viene registrato come tag. Le vulnerabilità dei container vengono registrate come riscontri statici (scansioni delle immagini) e quelle degli host come riscontri dinamici (scansioni di host in esecuzione).

Per ulteriori informazioni, consultare la [documentazione API di Lacework](https://docs.lacework.net/api/v2/docs).

## **Microsoft Defender**

Il connettore Microsoft Defender importa i riscontri di vulnerabilità dei dispositivi da **Microsoft Defender Vulnerability Management (MDVM)** — un riscontro per ogni combinazione di dispositivo / versione del software / CVE, inclusi gravità, punteggio CVSS, livello di sfruttabilità e gli aggiornamenti di sicurezza consigliati. DefectDojo rileverà i **gruppi di dispositivi** di Defender e creerà un Record per ciascuno; i dispositivi non assegnati a nessun gruppo di dispositivi vengono raccolti in un gruppo sintetico **Unassigned**.

**Nota:** questo connettore è distinto dal tipo di scansione basato su file **"MSDefender Parser"**, che importa file di Defender esportati manualmente. Scegliere un unico percorso di importazione per Prodotto per evitare riscontri duplicati.

#### Prerequisiti

Il tenant Microsoft deve disporre di una licenza attiva che includa le API di esportazione delle vulnerabilità di Defender: **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, oppure MDE P1/P2 con l'add-on MDVM. (Lo SKU *Add-on* di MDVM da solo non è sufficiente — richiede Defender for Endpoint Plan 2 come base.)

Il connettore si autentica come **registrazione dell'app** (app registration) di Microsoft Entra ID tramite il flusso client credentials. Per crearne una:

1. Nel [portale di Azure](https://portal.azure.com), aprire **App registrations > New registration**. Assegnare un nome (ad esempio `defectdojo-connector`), lasciare i valori predefiniti e selezionare **Register**.
2. Nella pagina **Overview** dell'app, annotare l'**Application (client) ID** e il **Directory (tenant) ID**.
3. Aprire **API permissions > Add a permission > APIs my organization uses** e cercare **WindowsDefenderATP**. Se non compare, il backend Defender del tenant non è ancora stato predisposto: verificare che la licenza sia attiva, aprire una volta [security.microsoft.com](https://security.microsoft.com) e riprovare dopo qualche minuto.
4. Scegliere **Application permissions** (*non* Delegated — i permessi Delegated non compaiono mai nel token di servizio del connettore), espandere **Vulnerability**, selezionare **Vulnerability.Read.All** e scegliere **Add permissions**.
5. Selezionare **Grant admin consent** e confermare. La colonna Status deve mostrare un segno di spunta verde — senza questo passaggio, ogni chiamata API restituisce un errore 403.
6. Aprire **Certificates & secrets > New client secret**, impostare una scadenza e copiare subito il **Value** del client secret (viene mostrato una sola volta). Il connettore smette di funzionare alla scadenza del client secret, quindi prendere nota della data.

#### Mappature del connettore

1. Inserire `https://api.security.microsoft.com` nel campo **Posizione**.
2. Inserire il **Directory (tenant) ID** nel campo **Tenant ID**.
3. Inserire l'**Application (client) ID** nel campo **Client ID**.
4. Inserire il valore del client secret nel campo **Client Secret**.
5. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni gruppo di dispositivi Defender diventa un Record. Microsoft rigenera lo snapshot delle vulnerabilità letto dal connettore circa ogni 6 ore, e i dispositivi appena registrati possono impiegare fino a ~24 ore per produrre i primi dati di vulnerabilità — è normale che un tenant appena creato esegua legittimamente un Sync con zero riscontri finché i dispositivi non vengono registrati e valutati. Anche l'attivazione della licenza può richiedere ~20 minuti o più per propagarsi all'API (gli errori "No active license found" durante questo periodo si risolvono da soli).

## **Microsoft Defender for Cloud**

Il connettore Microsoft Defender for Cloud importa i riscontri di vulnerabilità di **Microsoft Defender Vulnerability Management (MDVM)** così come esposti da Defender for Cloud — sia i riscontri **server** (CVE del sistema operativo e del software installato sulle VM di Azure) sia i riscontri di **registro dei container** (CVE delle immagini container), inclusi gravità, punteggio CVSS, il pacchetto o l'immagine interessati e la remediation. DefectDojo rileva le **sottoscrizioni** di Azure che la service principal può leggere e crea un Record per ogni sottoscrizione abilitata.

**Nota:** questo connettore è distinto dal connettore **Microsoft Defender**, che importa i riscontri dei dispositivi dall'API di Defender for Endpoint. Defender for Cloud è un prodotto Azure con una superficie API diversa (Azure Resource Manager / Resource Graph) e un modello di permessi diverso (Azure RBAC). Eseguire quello adatto in base a dove risiedono i riscontri — o entrambi, se si utilizzano entrambi i prodotti.

#### Prerequisiti

Sono necessarie una o più **sottoscrizioni di Azure con Microsoft Defender for Cloud abilitato**, con i piani Defender pertinenti attivati per le risorse da scansionare (in **Microsoft Defender for Cloud > Environment settings**, quindi selezionare la sottoscrizione):

* **Defender for Servers (Plan 2)** — riscontri CVE del sistema operativo e del software delle VM di Azure (scansione delle vulnerabilità senza agente).
* **Defender for Containers** — riscontri CVE delle immagini del registro dei container.

I riscontri di valutazione delle vulnerabilità SQL e di configurazione/postura **non** vengono importati intenzionalmente — questo connettore importa solo le vulnerabilità CVE.

Il connettore si autentica come **registrazione dell'app** (app registration) di Microsoft Entra ID tramite il flusso client credentials:

1. Nel [portale di Azure](https://portal.azure.com), aprire **App registrations > New registration**. Assegnare un nome (ad esempio `defectdojo-connector`), lasciare i valori predefiniti e selezionare **Register**.
2. Nella pagina **Overview** dell'app, annotare l'**Application (client) ID** e il **Directory (tenant) ID**.
3. Aprire **Certificates & secrets > New client secret**, impostare una scadenza e copiare subito il **Value** del client secret (viene mostrato una sola volta). Il connettore smette di funzionare alla scadenza del client secret, quindi prendere nota della data.
4. Concedere all'app l'accesso in lettura a ogni sottoscrizione da importare: aprire **Subscriptions**, selezionare la sottoscrizione, quindi **Access control (IAM) > Add > Add role assignment**. Selezionare il ruolo **Security Reader** (o **Reader**) e, nella scheda **Members**, assegnarlo all'app creata — cercarla per **nome** o **object ID** dell'app, poiché il selettore non corrisponde al client ID. Ripetere per ogni sottoscrizione.

A differenza del connettore Microsoft Defender basato sui dispositivi, non sono richiesti permessi API né il consenso dell'amministratore: l'accesso a Defender for Cloud è governato interamente dall'assegnazione di ruolo Azure RBAC descritta sopra.

#### Mappature del connettore

1. Inserire `https://management.azure.com` nel campo **Posizione**. (Per i cloud sovrani, utilizzare l'endpoint ARM corrispondente, ad esempio `https://management.usgovcloudapi.net`.)
2. Inserire il **Directory (tenant) ID** nel campo **Tenant ID**.
3. Inserire l'**Application (client) ID** nel campo **Client ID**.
4. Inserire il valore del client secret nel campo **Client Secret**.
5. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni sottoscrizione Azure abilitata diventa un Record. I riscontri vengono letti tramite Azure Resource Graph, quindi emergono rapidamente non appena Defender for Cloud ha scansionato le risorse — ma le scansioni stesse vengono eseguite secondo la pianificazione di Microsoft: le immagini del registro dei container vengono di solito scansionate entro un'ora dal push, mentre la prima scansione delle vulnerabilità senza agente di una VM può richiedere diverse ore. Una sottoscrizione appena abilitata eseguirà legittimamente un Sync con zero riscontri finché le sue risorse non saranno state scansionate.

## **MobSF**

Il connettore MobSF utilizza l'API REST di [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) per importare i risultati dell'analisi statica di applicazioni mobili (APK/IPA). DefectDojo rileva ogni app scansionata sull'istanza MobSF e crea un Record per ciascuna, quindi importa i riscontri di analisi statica di quell'app.

#### Prerequisiti

È necessaria la **chiave API REST** di MobSF. Si trova nella home page di MobSF sotto **API** (indicata anche nella documentazione di MobSF come valore `Authorization`). La chiave viene inviata a ogni richiesta e non viene mai registrata nei log.

#### Mappature del connettore

1. Inserire l'URL di base di MobSF nel campo **Posizione** (ad esempio `https://mobsf.example.com`).
2. Nel campo **Segreto**, inserire la chiave API REST di MobSF.
3. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

DefectDojo mappa ogni **app** scansionata a un Record e ne importa i riscontri dal report JSON di MobSF in diverse sezioni — permessi dell'applicazione, analisi del codice, il certificato di firma, il manifest Android, l'utilizzo delle API Android e l'analisi binaria. Ogni riscontro viene taggato con **CWE 919** (mobile), e la sua gravità proviene dalla valutazione propria di MobSF (high, warning, info, secure/good) — un permesso *dangerous* viene trattato come Alta. I riscontri vengono registrati come riscontri statici e deduplicati in base a scan, sezione, titolo, gravità e percorso del file.

Per maggiori informazioni, vedere la [documentazione dell'API REST di MobSF](https://mobsf.github.io/docs/#/rest_api).

## **NeuVector**

Il connettore NeuVector utilizza l'API REST del controller di [NeuVector](https://github.com/neuvector/neuvector) per importare le **scansioni di vulnerabilità delle immagini** container. DefectDojo rileva ogni immagine scansionata da NeuVector e crea un Record per ciascuna, quindi importa il report di scansione di quell'immagine come riscontri.

#### Prerequisiti

È necessario un **nome utente e una password** NeuVector per un account del controller con il permesso di leggere i risultati delle scansioni. Il connettore effettua l'accesso con queste credenziali per ottenere un token di sessione; la password e il token non vengono mai registrati nei log.

#### Mappature del connettore

1. Inserire l'URL del controller NeuVector nel campo **Posizione**, includendo la porta dell'API REST — ad esempio `https://neuvector.example.com:10443`.
2. Inserire lo **Username** e la **Password** del controller.
3. Se il controller utilizza un certificato autofirmato, impostare **Skip TLS Verification** su `true`.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

DefectDojo mappa ogni **immagine** scansionata a un Record e ogni **CVE** nel suo report di scansione a un riscontro. La gravità proviene dalla valutazione propria di NeuVector, e vengono riportati il pacchetto e la versione interessati, il punteggio e il vettore CVSSv3, la versione corretta (come mitigazione) e il link di riferimento. I riscontri vengono deduplicati in base a immagine, CVE, pacchetto, versione e gravità.

Per maggiori informazioni, vedere la [documentazione dell'API di NeuVector](https://open-docs.neuvector.com/automation/automation).

## **Nuclei (ProjectDiscovery Cloud)**

Il connettore Nuclei utilizza l'API REST della ProjectDiscovery Cloud Platform (PDCP) per recuperare i risultati di scansione di [nuclei](https://github.com/projectdiscovery/nuclei) dall'account PDCP. DefectDojo rileva ogni scansione presente nell'account e crea un Record separato per ogni **scansione**.

#### Prerequisiti

È necessaria una **chiave API** di ProjectDiscovery Cloud. Si consiglia di creare un account di servizio dedicato per DefectDojo, in modo da distinguere chiaramente l'attività automatizzata dalle azioni manuali del team. Generare una chiave da **Settings > API Key** nell'interfaccia di ProjectDiscovery Cloud ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). I risultati raggiungono PDCP sia dalle scansioni hosted sia dalla CLI di nuclei eseguita con `-dashboard`.

#### Mappature del connettore

1. Inserire l'URL di base dell'API PDCP nel campo **Posizione**: `https://api.projectdiscovery.io`.
2. Inserire la **chiave API** nel campo **Segreto**.
3. Facoltativamente, inserire un **Team ID** per limitare la sincronizzazione a un'area di lavoro di team (indicata in **Settings > Team**). Se lasciato vuoto, DefectDojo sincronizza l'area di lavoro personale.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

DefectDojo mappa ogni **scansione** PDCP come Record separato e importa i riscontri di quella scansione per ogni livello di gravità, inclusa quella informativa.

## **OpenVAS / Greenbone**

Il connettore OpenVAS / Greenbone importa i **riscontri di vulnerabilità di rete** da un'istanza Greenbone (Greenbone Community Edition o Greenbone Enterprise). Comunica con `gvmd` tramite **GMP (Greenbone Management Protocol)** — un protocollo XML su socket TLS, non HTTP — e sincronizza l'intera istanza: enumera le **task** di scansione e crea un prodotto DefectDojo per ciascuna, importando i risultati dell'ultimo report di ogni task.

#### Prerequisiti

Un **utente GMP** di Greenbone (nome utente + password) e l'accesso di rete alla porta TLS GMP di gvmd (predefinita **9390**). Lo stack compose di Greenbone Community Edition espone gvmd tramite un socket unix, quindi per raggiungerlo da un connettore in rete è necessario eseguire il connettore dove può accedere al socket, oppure esporre la porta TLS GMP (ad esempio un bridge TLS `socat` verso `gvmd.sock`).

#### Mappature del connettore

1. Inserire l'host di gvmd nel campo **Posizione** (host o `host:port`).
2. Inserire lo **Username** e la **Password** GMP.
3. Facoltativamente, impostare la **Porta GMP** (predefinita 9390).
4. Per il certificato autofirmato predefinito di gvmd, fornire un **Certificato CA (PEM)** con cui verificare, oppure impostare **Skip TLS Verification** su `true`.
5. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni task Greenbone diventa un Record. I riscontri provengono dall'ultimo report completato della task — uno per ogni `<result>`. La gravità viene ricavata dal livello di minaccia del risultato (i livelli informativi `Log`/`Debug` di Greenbone vengono mappati su Info), con il punteggio CVSS numerico registrato; i riferimenti CVE diventano identificativi di vulnerabilità, la soluzione dell'NVT diventa la mitigazione, e l'host/porta di ogni risultato diventa un endpoint.

## Probely

Questo connettore utilizza l'API REST di Probely per recuperare i dati.

​**Mappature del connettore**

1. Inserire l'indirizzo del server API appropriato nel campo **Posizione**. (in alternativa <https://api.us.probely.com/> oppure <https://api.eu.probely.com/> )
2. Inserire una chiave API valida nel campo **Segreto**.

È possibile trovare una chiave API nel menu User > API Keys di Probely.  
Vedere la [documentazione di Probely](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key) per maggiori informazioni.

## Prowler

Il connettore Prowler utilizza l'API REST di **Prowler App** per importare i riscontri di postura di sicurezza cloud (CSPM) da un'istanza Prowler App self-hosted. DefectDojo rileva ogni **provider** (account cloud) di Prowler come Record e importa i riscontri **FAIL** dell'ultima scansione completata di quel provider.

#### Prerequisiti

È necessaria un'istanza **Prowler App** self-hosted in esecuzione, e un'email + password utente (per l'autenticazione JWT) oppure una **chiave API** di Prowler App. I riscontri compaiono solo dopo aver collegato un account cloud (AWS, GCP, Azure, Kubernetes, ...) in Prowler App ed eseguito una scansione.

#### Mappature del connettore

1. Inserire l'URL di Prowler App nel campo **Posizione** (ad esempio `https://prowler.your-company.com`).
2. Per l'autenticazione JWT, inserire l'**Email** e la **Password** dell'utente Prowler App. In alternativa, lasciare questi campi vuoti e inserire una **API Key** di Prowler App. Se vengono forniti entrambi, viene utilizzata l'email/password (JWT).
3. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati. I riscontri al di sotto della gravità selezionata non vengono importati.

DefectDojo crea un Record per ogni provider Prowler e importa i riscontri FAIL dell'ultima scansione completata, mappando le gravità di Prowler sulle gravità di DefectDojo, la risorsa cloud interessata (ARN/resource id) come componente, e la remediation e il rischio del check nel riscontro. I riscontri silenziati (muted) vengono saltati. Account cloud, regione e servizio vengono allegati come tag.

Per maggiori informazioni, vedere la **[documentazione dell'API di Prowler App](https://api.prowler.com/api/v1/docs)**.

## Qualys

Il connettore Qualys importa le **rilevazioni di vulnerabilità host di VMDR** — ciascuna unita ai metadati della Qualys KnowledgeBase (QID) — dalla Qualys Cloud Platform. DefectDojo crea un Record per ogni **host** Qualys nella sottoscrizione.

#### Prerequisiti

Un account utente Qualys con **accesso all'API VMDR**, e l'**URL del server API (platform)** della sottoscrizione — che varia in base alla sottoscrizione. Si trova nell'interfaccia di Qualys sotto **Help > About**, oppure nella pagina [Platform Identification](https://www.qualys.com/platform-identification/) di Qualys (ad esempio `https://qualysapi.qualys.com` per US Platform 1, o `https://qualysapi.qg2.apps.qualys.com` per US Platform 2).

#### Mappature del connettore

1. Inserire l'URL del server API Qualys nel campo **Posizione** (ad esempio `https://qualysapi.qualys.com`).
2. Inserire il nome utente dell'API Qualys nel campo **Username**.
3. Inserire la password dell'API Qualys nel campo **Segreto**.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni host Qualys diventa un Record. Le rilevazioni che Qualys ha contrassegnato come **Fixed** vengono escluse, quindi la reimportazione chiude i riscontri risolti.

## **Quay**

Il connettore Quay utilizza l'API REST di Project Quay per rilevare i repository di container e importare i report di vulnerabilità prodotti dallo scanner **Clair** integrato in Quay. DefectDojo crea un Record per ogni **repository** Quay e, a ogni Sync, legge il report di sicurezza Clair del manifest immagine di ogni tag attivo.

#### Prerequisiti

La scansione di sicurezza (Clair) deve essere abilitata sull'istanza Quay, ed è necessario un **token di accesso OAuth 2** di Quay:

* In Quay, creare (o aprire) un'Organization, andare su **Applications**, creare un'applicazione OAuth, quindi **Generate Token** con almeno lo scope **Read repositories**. Si consiglia un'applicazione dedicata per DefectDojo.
* Il token viene inviato come Bearer token a ogni richiesta e non viene mai registrato nei log.

#### Mappature del connettore

1. Inserire l'URL di base di Quay nel campo **Posizione**, ad esempio `https://quay.io` oppure l'istanza self-hosted `https://quay.example.com`. L'URL deve essere HTTPS; non includere un percorso API finale — DefectDojo costruisce automaticamente i percorsi API.
2. Inserire il token di accesso OAuth nel campo **Segreto**.
3. Facoltativamente, impostare un **Namespace** per limitare il rilevamento a una singola organizzazione o utente Quay. Lasciare vuoto per rilevare tutti i repository che il token può leggere.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

DefectDojo mappa ogni **repository** Quay a un Record. Per ogni repository elenca i tag attivi, li deduplica ai rispettivi manifest immagine univoci (un manifest condiviso da più tag viene scansionato una sola volta), e legge il report Clair di ogni manifest. I manifest che Clair non ha ancora finito di scansionare (ad esempio una manifest list multi-architettura, o un'immagine ancora in coda) vengono saltati fino a un Sync successivo. Ogni vulnerabilità Clair diventa un riscontro — il pacchetto interessato è il componente, la versione corretta diventa la mitigazione, e le gravità **Negligible**/**Unknown** di Clair vengono registrate come **Informativa**.

Vedere la [documentazione dell'API di Project Quay](https://docs.projectquay.io/api_quay.html) e la [documentazione di Clair](https://quay.github.io/clair/) per maggiori informazioni.

## **Rapid7 InsightAppSec**

Il connettore Rapid7 InsightAppSec importa i **riscontri di vulnerabilità DAST** dalla piattaforma cloud InsightAppSec, arricchiti con i metadati del modulo di attacco (ad esempio *SQL Injection*), i punteggi CVSS e le evidenze raccolte dalla scansione. DefectDojo crea un Record per ogni **app** InsightAppSec.

**Nota:** questo connettore è distinto dal connettore **Rapid7 InsightVM** descritto più avanti — InsightAppSec è il prodotto DAST cloud di Rapid7 sulla piattaforma Insight, mentre i riscontri di InsightVM provengono dalla propria Security Console.

#### Prerequisiti

Un account della piattaforma Insight con InsightAppSec, e una **chiave API** della piattaforma: nella [piattaforma Rapid7 Insight](https://insight.rapid7.com), aprire il menu delle impostazioni (icona a forma di ingranaggio) > **API Keys** e generare una **User Key** (qualsiasi ruolo) o una **Organization Key** (amministratori della piattaforma). Copiare la chiave quando viene mostrata — viene visualizzata una sola volta.

È inoltre necessaria la **regione** della piattaforma, visibile nell'URL Insight (ad esempio `us`, `us2`, `us3`, `eu`, `ca`, `au`, o `ap`).

#### Mappature del connettore

1. Inserire l'endpoint API della propria regione nel campo **Posizione** — ad esempio `https://us.api.insight.rapid7.com` (sostituire `us` con la propria regione).
2. Inserire la chiave API della piattaforma Insight nel campo **API Key**.
3. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni app InsightAppSec diventa un Record. Vengono importate solo le vulnerabilità **aperte** (Unreviewed o Verificato) — i riscontri che Rapid7 ha contrassegnato come Remediated, Falso positivo, Ignored o Duplicato vengono esclusi, quindi la reimportazione li chiude in DefectDojo. Le gravità vengono mappate direttamente (`SAFE` e `INFORMATIONAL` vengono importati come Info).

## **Rapid7 InsightVM**

Il connettore Rapid7 InsightVM importa i riscontri di vulnerabilità degli asset dalla **Security Console** InsightVM (API v3), arricchiti con il catalogo globale di vulnerabilità della console. DefectDojo crea un Record per ogni **site** InsightVM.

#### Prerequisiti

Accesso di rete da DefectDojo alla Security Console, e un **account utente** della console — il suo login viene utilizzato per l'autenticazione HTTP Basic. L'API della console viene servita per impostazione predefinita sulla porta **3780**.

#### Mappature del connettore

1. Inserire l'URL della Security Console, porta inclusa, nel campo **Posizione** — ad esempio `https://console.example.com:3780`.
2. Inserire il nome utente della console nel campo **Username**.
3. Inserire la password della console nel campo **Segreto**.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni site InsightVM diventa un Record; il connettore percorre gli asset del site e ne importa i riscontri vulnerabili.

## **runZero**

Il connettore runZero utilizza la Export API di runZero per sincronizzare in DefectDojo l'inventario asset dell'intera organizzazione. È principalmente un connettore di **asset**: DefectDojo rileva ogni asset e crea un Record per ciascuno, raggruppato in un Tipo di Prodotto in base al **site** runZero. Facoltativamente può anche importare le vulnerabilità di runZero come riscontri.

#### Prerequisiti

È necessario un **Export Token** dell'organizzazione da runZero (Account → API), con prefisso `XT`. Il token è associato all'organizzazione (l'organizzazione è codificata nel token), è di sola lettura, e viene inviato come Bearer token — non viene mai registrato nei log. È disponibile un livello community/starter.

#### Mappature del connettore

1. Inserire l'URL della console runZero nel campo **Posizione**, ad esempio `https://console.runzero.com`. L'URL deve essere HTTPS.
2. Inserire l'Export Token nel campo **Segreto**.
3. Facoltativamente, impostare **Importazione vulnerabilità** su `true` per importare come riscontri anche le vulnerabilità di runZero; lasciare vuoto per sincronizzare solo gli asset.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri di vulnerabilità importati (si applica solo quando le vulnerabilità vengono importate).

DefectDojo mappa ogni **asset** runZero a un Record (VEP): il nome visualizzato proviene dal nome o dall'indirizzo dell'asset, e il suo site, tipo, SO, indirizzi e tag vengono allegati come attributi; il **site** dell'asset diventa il suo Tipo di Prodotto. Gli asset vengono sincronizzati tramite un'esportazione completa che DefectDojo riconcilia (aggiunte/rimozioni). Quando **Importazione vulnerabilità** è abilitata, ogni vulnerabilità runZero diventa un riscontro sul relativo asset — mappando gravità, punteggio CVSS, CVE, endpoint del servizio interessato (`protocol://address:port`) e la remediation.

Vedere la [documentazione dell'API di runZero](https://help.runzero.com/) per maggiori informazioni.

## **Semgrep**

Questo connettore utilizza l'API REST di Semgrep per recuperare i dati.

#### Mappature del connettore

Inserire `https://semgrep.dev/api/v1/` nel campo **Posizione**.

1. Inserire una chiave API valida nel campo **Segreto**. Si trova nella pagina Tokens:   
​  
"Settings" nella barra di navigazione a sinistra > Tokens > Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

Vedere la [documentazione di Semgrep](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list) per maggiori informazioni.

## **ServiceNow CMDB**

Il connettore ServiceNow CMDB è un **Asset Connector**: invece di importare riscontri, legge gli elementi di configurazione (CI) dal Configuration Management Database di ServiceNow e crea un Asset DefectDojo per ogni CI, raggruppati in Organizzazioni in base alla classe del CI. Non viene importato alcun riscontro.

#### Prerequisiti

È necessaria un'istanza ServiceNow e un account in grado di leggere le tabelle CMDB tramite la Table API di ServiceNow. Si consiglia un account di servizio dedicato e di sola lettura per DefectDojo. L'account necessita dell'accesso in lettura alle tabelle `cmdb_ci` da importare.

#### Mappature del connettore

1. Inserire l'URL dell'istanza ServiceNow nel campo **Posizione**: `https://{your-instance}.service-now.com`.
2. Selezionare o creare una **Tool Configuration** di ServiceNow contenente le credenziali dell'istanza (nome utente e password ServiceNow).

Ogni elemento di configurazione diventa un Record denominato come il CI, raggruppato in base alla sua **classe di CI** (ad esempio, applicazione, server o business service). Discovery e Sync riconciliano l'elenco dei CI: i nuovi CI compaiono come Record `NEW`, e un CI rimosso dal CMDB viene contrassegnato come `MISSING` al Sync successivo, in modo che il team possa valutarlo. DefectDojo non elimina mai silenziosamente un Prodotto.

## **Shodan**

Il connettore Shodan utilizza l'API REST di Shodan per importare le vulnerabilità (CVE) che Shodan ha osservato sugli host esposti a internet. Viene fornita una query di ricerca Shodan che limita l'importazione ai propri asset; DefectDojo crea un Record per ogni host corrispondente e ne importa i CVE come riscontri.

#### Prerequisiti

È necessaria una chiave API Shodan, disponibile nella pagina **Account** di Shodan. La ricerca di host con dati di vulnerabilità richiede un abbonamento Shodan o un piano API a pagamento — il livello gratuito non consente di scorrere le pagine dei risultati di ricerca.

#### Mappature del connettore

1. Inserire `https://api.shodan.io` nel campo **Posizione**.
2. Inserire la propria chiave API Shodan nel campo **API Key**.
3. Nel campo **Query di ricerca**, inserire una query Shodan che limiti l'importazione agli asset dell'organizzazione — ad esempio `hostname:example.com`, `net:203.0.113.0/24`, oppure `org:"Example Inc"`. Vengono importati solo gli host corrispondenti a questa query, quindi mantenerla limitata all'infrastruttura di proprietà.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni host corrispondente diventa un Record, e ogni CVE rilevato da Shodan sui servizi esposti di quell'host viene importato come riscontro — la gravità è derivata dal punteggio CVSS, con il contesto EPSS e CISA KEV incluso ove disponibile. Ogni pagina di risultati di ricerca consuma un credito di query Shodan.

## SonarQube

Il connettore SonarQube può recuperare dati sia da un account SonarCloud sia da un'istanza locale di SonarQube.

**Per gli utenti SonarCloud:**

1. Inserire https://sonarcloud.io/ nel campo Posizione.
2. Inserire una **chiave API** valida nel campo Segreto.

**Per gli utenti SonarQube (on-premise):**

1. Inserire l'URL di base dell'istanza SonarQube nel campo Posizione: ad esempio `https://my.sonarqube.com/`
2. Inserire una **chiave API** valida nel campo Segreto. Dovrà essere un **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [API Token Type](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

Il token dovrà avere accesso a Projects, Vulnerabilities e Hotspots all'interno di Sonar.

I token API si trovano e si generano tramite **My Account -> Security -> Generate Token** nell'app SonarQube. Per maggiori informazioni, [vedere la documentazione di SonarQube](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

## **Snyk**

Il connettore Snyk utilizza l'API REST di Snyk per recuperare i dati.

#### Mappature del connettore

1. Inserire **[https://api.snyk.io/rest](https://api.snyk.io/v1)** oppure **[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** (per un deployment regionale UE) nel campo **Posizione**.
2. Inserire una chiave API valida nel campo **Segreto**. I token API si trovano nella pagina **[Account Settings](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)** [dell'utente](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token) in Snyk.

Vedere la [documentazione dell'API di Snyk](https://docs.snyk.io/snyk-api) per maggiori informazioni.

## **Socket**

Il connettore Socket utilizza l'API di [Socket.dev](https://socket.dev) per importare **riscontri sulla supply chain del software** — gli avvisi di Socket sulle dipendenze del progetto (malware, typosquatting, script di installazione, vulnerabilità note e oltre 70 altre categorie). DefectDojo individua ogni repository nelle organizzazioni a cui il token ha accesso e crea un Record per ciascuno, quindi importa gli avvisi dall'ultima scansione completa di quel repository.

#### Prerequisiti

È necessario un **token API** di Socket, un token dell'organizzazione creato nella dashboard di Socket in **Settings → API Tokens** (con gli ambiti `repo:list` e di lettura full-scan). Il token viene inviato come bearer token e non viene mai registrato nei log.

#### Mappature del connettore

1. Lasciare vuoto il campo **Posizione** per utilizzare `https://api.socket.dev/v0`, oppure inserirlo esplicitamente.
2. Inserire il token API di Socket nel campo **Segreto**.
3. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

DefectDojo mappa ogni **repository** su un Record e importa gli avvisi della sua scansione completa più recente. Ogni avviso diventa un riscontro: la gravità deriva dalla valutazione propria di Socket (bassa, media, alta, critica), il pacchetto interessato diventa il componente e un PURL, la categoria dell'avviso (rischio di supply chain, qualità, manutenzione, vulnerabilità, licenza) viene registrata come tag, e i dettagli dell'avviso confluiscono nella descrizione. I riscontri vengono registrati come riscontri statici e deduplicati in base alla chiave dell'avviso di Socket.

Per maggiori informazioni, consultare la [documentazione dell'API Socket](https://docs.socket.dev/reference).

## **Sonatype IQ**

Il connettore Sonatype IQ utilizza l'API REST di Sonatype IQ Server (Nexus Lifecycle) per importare le vulnerabilità dei componenti open source. Il connettore elenca tutte le applicazioni presenti nell'organizzazione IQ e, per ciascuna, importa le vulnerabilità dei componenti dal report più recente di quell'applicazione, nella fase del ciclo di vita configurata. DefectDojo crea automaticamente un Record per ogni applicazione — non è richiesta alcuna configurazione per applicazione.

#### Prerequisiti

È necessario un account utente Sonatype IQ con l'autorizzazione **View IQ Elements** sulle applicazioni da importare. Sonatype consiglia di autenticarsi con un **token utente** (generato in **My Profile > User Token** in IQ Server) anziché con una password; le due parti del token corrispondono ai campi Nome utente e Token utente riportati di seguito. Il connettore funziona sia con IQ Server self-hosted sia con istanze ospitate da Sonatype (SaaS).

#### Mappature del connettore

1. Nel campo **Posizione**, inserire l'URL di base del proprio IQ Server — per un server self-hosted, `https://iq.example.com`; per un'istanza ospitata da Sonatype, `https://<tenant>.sonatype.app/platform`.
2. Inserire l'utente IQ (o la parte user-code del proprio token utente) nel campo **Nome utente**.
3. Inserire il token utente IQ (o la password) nel campo **Token utente**.
4. Facoltativamente, impostare una **Fase** per scegliere il report di quale fase del ciclo di vita viene importato per applicazione (`build`, `stage-release`, `release` e così via). Lasciare vuoto per utilizzare `build`.
5. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni applicazione diventa un Record, e ogni problema di sicurezza nel report più recente di quell'applicazione per la fase selezionata viene importato come riscontro. La gravità è derivata dal punteggio numerico del problema, e i riferimenti CVE, il CWE, il vettore CVSS e l'URL del pacchetto (PURL) del componente interessato sono inclusi ove disponibili.
## **Sysdig Secure**

Il connettore Sysdig Secure importa **riscontri di vulnerabilità container / CNAPP** dall'API di gestione delle vulnerabilità di Sysdig Secure. Sincronizza l'intero account negli ambiti configurati e crea un prodotto DefectDojo per ogni raggruppamento di asset sottoposto a scansione.

#### Prerequisiti

Un **token API** di Sysdig Secure: in Sysdig Secure, andare su **Settings > Sysdig Secure API Token** e copiare il token. È inoltre necessario l'**URL della regione** Sysdig (ad esempio `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, oppure il proprio host on-premise).

#### Mappature del connettore

1. Inserire l'URL di regione/base di Sysdig nel campo **Posizione**.
2. Inserire il token API nel campo **Segreto**.
3. Facoltativamente, impostare gli **Ambiti** — un elenco separato da virgole di `runtime`, `registry` e/o `pipeline` (lasciare vuoto per `runtime`, l'ambito dei carichi di lavoro distribuiti).
4. Facoltativamente, impostare il **Raggruppamento prodotti runtime** — come i risultati runtime vengono mappati sui prodotti: `cluster`, `namespace`, `workload` o `image` (lasciare vuoto per `namespace`). I risultati di registry e pipeline vengono sempre raggruppati per repository dell'immagine.
5. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni raggruppamento di asset diventa un Record. Per ogni risultato di scansione, il connettore importa ogni pacchetto vulnerabile come riscontro. I riscontri **Runtime** (carichi di lavoro distribuiti) vengono registrati come riscontri dinamici e taggati con il relativo contesto di cluster / namespace / workload / container Kubernetes; i riscontri **registry** e **pipeline** vengono registrati come riscontri statici di scansione immagine. La gravità `NEGLIGIBLE` di Sysdig viene mappata su Info.

## Tenable

Il connettore Tenable utilizza l'API REST di **Tenable.io** per recuperare i dati. Le scansioni vengono recuperate dall'endpoint `/scans` di Tenable VM.

I connettori Tenable on-premise non sono al momento disponibili.

#### **Mappature del connettore**

1. Inserire <https://cloud.tenable.com> nel campo Posizione.
2. Inserire una **chiave API** valida nel campo Segreto.

Per maggiori informazioni, consultare la [documentazione dell'API di Tenable](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm).

## **Tenable Web App Scanning**

Il connettore Tenable Web App Scanning importa **riscontri di applicazioni web (DAST)** da Tenable Web App Scanning. Si tratta di un connettore separato rispetto a Tenable (Vulnerability Management): i due prodotti coprono asset diversi e vengono configurati in modo indipendente, quindi è possibile utilizzare l'uno, l'altro o entrambi.

DefectDojo crea un Record per ogni **applicazione web sottoposta a scansione**. Le applicazioni vengono individuate a partire dalle configurazioni di scansione di Web App Scanning; una configurazione mai eseguita non produce un Record finché non viene completata la prima scansione. Quando più configurazioni analizzano la stessa applicazione, condividono un unico Record.

#### Prerequisiti

**Chiavi API** Tenable (una chiave di accesso e una chiave segreta) per un utente con autorizzazioni Web App Scanning. In Tenable, andare su **My Account > API Keys** per generarle, e verificare che l'utente possa visualizzare le scansioni da importare — le chiavi limitate a Vulnerability Management non possono leggere i dati di Web App Scanning.

I connettori Tenable on-premise non sono al momento disponibili.

#### Mappature del connettore

1. Inserire <https://cloud.tenable.com> nel campo **Posizione**.
2. Inserire la propria **Chiave di accesso** e **Chiave segreta**.
3. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

I riscontri vengono importati con la gravità segnalata da Tenable per l'account, inclusa qualsiasi gravità che il team abbia riclassificato. Ogni riscontro riporta l'URL interessato come endpoint, il parametro di richiesta e il payload che lo hanno generato, e la prova e l'output di Tenable come passaggi per la riproduzione, insieme ai valori CWE, CVE, CVSS ed EPSS ove forniti dal plugin di rilevamento.

Vengono importati solo i riscontri attualmente aperti o riaperti. Un riscontro che Tenable ha contrassegnato come risolto viene chiuso in DefectDojo alla sincronizzazione successiva.

## **Veracode**

Il connettore Veracode importa i riscontri delle applicazioni dalla piattaforma Veracode, suddivisi per tipo di scansione nei tipi di riscontro **SAST**, **DAST**, **SCA** e **Manual**. DefectDojo crea un Record per ogni **applicazione** Veracode.

#### Prerequisiti

Generare una **credenziale API** di Veracode per un account in grado di visualizzare le applicazioni da importare: nella Veracode Platform, aprire il menu account > **API Credentials** e selezionare **Generate API Credentials** (vedere [Gestione delle credenziali API di Veracode](https://docs.veracode.com/r/c_api_credentials3)). Copiare sia l'**ID API** sia la **Chiave segreta API**, mostrata una sola volta.

#### Mappature del connettore

1. Inserire l'URL di base dell'API Veracode nel campo **Posizione**: `https://api.veracode.com` (regione commerciale), `https://api.veracode.eu` (regione europea) oppure `https://api.veracode.us` (regione federale statunitense).
2. Inserire l'ID API nel campo **ID API**.
3. Inserire la chiave segreta API nel campo **Segreto**.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati.

Ogni applicazione Veracode diventa un Record. Vengono importati solo i riscontri **aperti**, quindi una nuova importazione chiude i riscontri che Veracode segnala come risolti.

## **Wazuh**

Il connettore Wazuh utilizza Wazuh Indexer (OpenSearch) per recuperare i riscontri di vulnerabilità. Wazuh 4.8 e versioni successive memorizzano i CVE rilevati nell'Indexer anziché nell'API del server Wazuh, quindi questo connettore li legge direttamente dall'indice `wazuh-states-vulnerabilities-*`.

DefectDojo crea un Record per ogni agente Wazuh (endpoint) e importa i CVE rilevati da tale agente come riscontri, secondo una pianificazione.

#### Prerequisiti

Sono necessari:

* L'URL di base del proprio Wazuh Indexer, comprensivo di porta (l'Indexer è in ascolto sulla porta 9200 per impostazione predefinita). DefectDojo si collega direttamente all'Indexer, quindi questo endpoint deve essere raggiungibile da DefectDojo. Per le implementazioni self-managed, si tratta dell'host su cui è in esecuzione Wazuh Indexer. Per Wazuh Cloud, utilizzare l'endpoint dell'Indexer indicato nella console di Wazuh Cloud, distinto dall'URL della dashboard di Wazuh.
* Un utente e una password dell'Indexer con accesso in lettura all'indice `wazuh-states-vulnerabilities-*`. Si consiglia di creare un utente dedicato per DefectDojo.

Il rilevamento delle vulnerabilità deve essere abilitato in Wazuh affinché l'indice dello stato delle vulnerabilità venga popolato. Per maggiori informazioni, consultare la [documentazione di Wazuh sul rilevamento delle vulnerabilità](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html).

#### Mappature del connettore

1. Inserire l'URL di base del proprio Wazuh Indexer nel campo **Posizione**, comprensivo di schema e porta, ad esempio `https://your-indexer.example.com:9200`. Non includere un percorso finale. DefectDojo costruisce automaticamente i percorsi di ricerca.
2. Inserire il nome utente dell'Indexer nel campo **Nome utente**.
3. Inserire la password dell'Indexer nel campo **Password**.
4. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati. I riscontri al di sotto della gravità selezionata non verranno importati.

## Wiz

Per utilizzare il connettore Wiz è necessario creare un account di servizio: per maggiori informazioni, vedere la [documentazione di Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account). Per accedere alla documentazione è necessario un account Wiz.

L'account di servizio deve soddisfare tutti i seguenti requisiti. Un account di servizio privo anche di un solo requisito può comunque autenticarsi correttamente, ma non importerà nulla:

* **Tipo**: Custom Integration (GraphQL API).
* **Ambiti API**: come minimo `read:projects`, `read:issues` e `read:vulnerabilities`.
* **Visibilità del progetto**: l'account di servizio deve avere visibilità su ogni Wiz Project da importare (oppure su tutti i Project). Il connettore individua prima i Project Wiz e poi recupera i riscontri di ciascun Project — un account che può leggere gli issue ma non ha visibilità sui Project non individua alcun Project, quindi non c'è nulla da importare e nessuno dei due sistemi segnala un errore.

#### **Mappature del connettore**

1. Inserire l'ID client di Wiz nel campo ID client.
2. Inserire il Segreto client di Wiz nel campo Segreto.

## **YesWeHack**

Il connettore YesWeHack utilizza l'API REST di YesWeHack per importare i report dai programmi di bug bounty e vulnerability disclosure. DefectDojo crea un Record per ogni programma a cui il token ha accesso e ne importa i report come riscontri.

#### Prerequisiti

È necessario un **Personal Access Token (PAT)** di YesWeHack. È sufficiente l'accesso in lettura ai programmi. Alcuni account richiedono TOTP/MFA durante la creazione di un token; una volta creato, il connettore utilizza direttamente il valore del token.

1. In YesWeHack, aprire le impostazioni dell'account e andare su **API / Personal Access Tokens**.
2. Creare un token e copiarne il valore. Viene mostrato una sola volta.

#### Mappature del connettore

1. Inserire `https://api.yeswehack.com/` nel campo **Posizione**.
2. Inserire il proprio Personal Access Token nel campo **Segreto**.
3. Facoltativamente, impostare una **Gravità minima** per limitare i riscontri importati. I riscontri al di sotto della gravità selezionata non verranno importati.

DefectDojo crea un Record distinto per ogni programma a cui il token ha accesso, e importa ogni report come riscontro. La gravità del riscontro deriva dalla valutazione CVSS del report (con fallback sulla priorità di triage), e il suo stato riflette lo stato del workflow del report — ad esempio, i report risolti vengono importati come mitigati, mentre i report contrassegnati come non validi o fuori ambito vengono importati come inattivi.
