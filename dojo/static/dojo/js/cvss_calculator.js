
var response = '<!--'+
'  Copyright (c) 2015, FIRST.ORG, INC.'+
'  All rights reserved.'+
''+
'  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the'+
'  following conditions are met:'+
'  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following'+
'     disclaimer.'+
'  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the'+
'     following disclaimer in the documentation and/or other materials provided with the distribution.'+
'  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote'+
'     products derived from this software without specific prior written permission.'+
''+
'  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,'+
'  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE'+
'  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,'+
'  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR'+
'  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,'+
'  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE'+
'  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.'+
'-->'+
''+
'<style type="text/css">'+
'  #cvsscalculator { position: fixed; height: 70vh; width: 70%; position: absolute; background-color: #ffffff; border: 1px solid #d0d0d0 ;overflow-y:scroll; z-index: 42; padding: 10 px}'+
'  #cvssReference { font-size: 100%; }'+
'  fieldset { position: relative; background-color: #f2f2f2; margin-top: 50px; border:0; padding: 1em 0; }'+
'  fieldset legend { background-color: rgba(32, 166, 216, 0.75);; color: #ffffff; margin: 0; width: 100%; padding: 0.5em 0px; text-indent: 1em; }'+
'  fieldset div.metric { padding: 0; margin: 0.5em 0; }'+
''+
'@media only screen and (min-width:768px) {'+
'  fieldset div.column { width: 45%; margin: 0 0 0 1em; }'+
'  fieldset div.column-left { float: left; height: auto; }'+
'  fieldset div.column-right { float: right; height: auto; }'+
'}'+
'  fieldset h3 { font-size: 1em; margin: 0; padding-left: 0.1em; }'+
'  fieldset input { display: none; width:auto; }'+
'  fieldset label {'+
'    background: #cccccc; display: inline-block; margin: 3px; padding: 2px 5px; border: 0; cursor: pointer; font-size: 90%;'+
'    border-radius: 5px; color: #666666; border: 1px solid #999999;'+
'    user-select: none; -webkit-user-select: none; -moz-user-select: -moz-none; -ms-user-select: none; user-select: none;'+
'  }'+
'  fieldset label:hover { background: #666666; color: #ffffff; border: 1px solid #666666 }'+
'  fieldset input:checked + label { background: rgba(32, 166, 216, 0.75);; border: 1px solid rgba(32, 166, 216, 0.75); color: #ffffff; }'+
''+
'  #vector         { margin: 0 1em;padding:0; }'+
'  #vectorString   { display: none; border: 0; padding: 0; margin: 0; background-color: transparent; color: #ffffff; font-weight: bold;font-size:0.8em;width:80em;max-width:100%; }'+
''+
'  .scoreRating { position: absolute; top:-36px; right:0; padding: 0 0.4em; margin: 0 15px; border: 2px solid #666666; background: #dddddd;'+
'    font-size:11px; border-radius: 10px; width: 100px; height: auto; line-height: 150%; text-align: center; }'+
'  .scoreRating.none,'+
'  .scoreRating.low,'+
'  .scoreRating.medium,'+
'  .scoreRating.high,'+
'  .scoreRating.critical { color:#ffffff;}'+
''+
'  .scoreRating.none     { background:#53aa33; border:2px solid #53aa33; }'+
'  .scoreRating.low      { background:#ffcb0d; border:2px solid #ffcb0d; }'+
'  .scoreRating.medium   { background:#f9a009; border:2px solid #f9a009; }'+
'  .scoreRating.high     { background:#df3d03; border:2px solid #df3d03; }'+
'  .scoreRating.critical { background:#cc0500; border:2px solid #cc0500; }'+
'  .scoreRating span     { font-size: 150%; font-weight: bold; width: 100%; }'+
'  .needBaseMetrics      { text-align:center; line-height:100%; padding-top:5px; font-size:15px; }'+
''+
'  #baseMetricScore,'+
'  #temporalMetricScore,'+
'  #environmentalMetricScore { display: block; font-size: 32px; line-height: 32px; font-weight: normal; margin-top: 4px; }'+
''+
'  #baseSeverity,'+
'  #temporalSeverity,'+
'  #environmentalSeverity { font-size: 16px; font-weight: normal; margin-bottom: 5px; display: block; }'+
''+
'  div#scriptWarning { border: solid red 2px; background: #f5dddd; padding: 1em 1em 1em 1em; margin: 0.4em 0; }'+
''+
'</style>'+
''+
'<script>'+
'   document.querySelector("#cvsscalculator").style.display = "none";'+
'</script>'+
''+
''+
'<form action="#" id="cvsscalculator">'+
''+
''+
'<fieldset id="baseMetricGroup">'+
'  <legend id="baseMetricGroup_Legend" title="The Base Metric group represents the intrinsic  characteristics of a vulnerability that are constant over time and across user environments. Determine the vulnerable component and score Attack Vector, Attack Complexity, Privileges Required and User Interaction relative to this.">Base Score</legend>'+
''+
'  <div class="column column-left">'+
''+
'    <div class="metric">'+
'      <h3 id="AV_Heading" title="This metric reflects the context by which vulnerability exploitation is possible. The Base Score increases the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component.">Attack Vector (AV)</h3>'+
'      <input name="AV" value="N" id="AV_N" type="radio"><label for="AV_N" id="AV_N_Label" title="A vulnerability exploitable with network access means the vulnerable component is bound to the network stack and the attacker\'s path is through OSI layer 3 (the network layer). Such a vulnerability is often termed "remotely exploitable” and can be thought of as an attack being exploitable one or more network hops away.">Network (N)</label>'+
'      <input name="AV" value="A" id="AV_A" type="radio"><label for="AV_A" id="AV_A_Label" title="A vulnerability exploitable with adjacent network access means the vulnerable component is bound to the network stack, however the attack is limited to the same shared physical (e.g. Bluetooth, IEEE 802.11), or logical (e.g. local IP subnet) network, and cannot be performed across an OSI layer 3 boundary (e.g. a router).">Adjacent (A)</label>'+
'      <input name="AV" value="L" id="AV_L" type="radio"><label for="AV_L" id="AV_L_Label" title="A vulnerability exploitable with local access means that the vulnerable component is not bound to the network stack, and the attacker’s path is via read/write/execute capabilities. In some cases, the attacker may be logged in locally in order to exploit the vulnerability, otherwise, she may rely on User Interaction to execute a malicious file.">Local (L)</label>'+
'      <input name="AV" value="P" id="AV_P" type="radio"><label for="AV_P" id="AV_P_Label" title="A vulnerability exploitable with physical access requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent.">Physical (P)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="AC_Heading" title="This metric describes the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability. Such conditions may require the collection of more information about the target, the presence of certain system configuration settings, or computational exceptions.">Attack Complexity (AC)</h3>'+
'      <input name="AC" value="L" id="AC_L" type="radio"><label for="AC_L" id="AC_L_Label" title="Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component.">Low (L)</label>'+
'      <input name="AC" value="H" id="AC_H" type="radio"><label for="AC_H" id="AC_H_Label" title="A successful attack depends on conditions beyond the attacker\'s control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may require the attacker: to perform target-specific reconnaissance; to prepare the target environment to improve exploit reliability; or to inject herself into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g. a man in the middle attack).">High (H)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="PR_Heading" title="This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. This Base Score increases as fewer privileges are required.">Privileges Required (PR)</h3>'+
'      <input name="PR" value="N" id="PR_N" type="radio"><label for="PR_N" id="PR_N_Label" title="The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.">None (N)</label>'+
'      <input name="PR" value="L" id="PR_L" type="radio"><label for="PR_L" id="PR_L_Label" title="The attacker is authorized with (i.e. requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.">Low (L)</label>'+
'      <input name="PR" value="H" id="PR_H" type="radio"><label for="PR_H" id="PR_H_Label" title="The attacker is authorized with (i.e. requires) privileges that provide significant (e.g. administrative) control over the vulnerable component that could affect component-wide settings and files.">High (H)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="UI_Heading" title="This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner. The Base Score is highest when no user interaction is required.">User Interaction (UI)</h3>'+
'      <input name="UI" value="N" id="UI_N" type="radio"><label for="UI_N" id="UI_N_Label" title="The vulnerable system can be exploited without any interaction from any user.">None (N)</label>'+
'      <input name="UI" value="R" id="UI_R" type="radio"><label for="UI_R" id="UI_R_Label" title="Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.">Required (R)</label>'+
'    </div>'+
''+
'  </div>'+
''+
''+
'  <div class="column column-right">'+
''+
'    <div class="metric">'+
'      <h3 id="S_Heading" title="Does a successful attack impact a component other than the vulnerable component? If so, the Base Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.">Scope (S)</h3>'+
'      <input name="S" value="U" id="S_U" type="radio"><label for="S_U" id="S_U_Label" title="An exploited vulnerability can only affect resources managed by the same authority. In this case the vulnerable component and the impacted component are the same.">Unchanged (U)</label>'+
'      <input name="S" value="C" id="S_C" type="radio"><label for="S_C" id="S_C_Label" title="An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component. In this case the vulnerable component and the impacted component are different.">Changed (C)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="C_Heading" title="This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.">Confidentiality (C)</h3>'+
'      <input name="C" value="N" id="C_N" type="radio"><label for="C_N" id="C_N_Label" title="There is no loss of confidentiality within the impacted component.">None (N)</label>'+
'      <input name="C" value="L" id="C_L" type="radio"><label for="C_L" id="C_L_Label" title="There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is constrained. The information disclosure does not cause a direct, serious loss to the impacted component.">Low (L)</label>'+
'      <input name="C" value="H" id="C_H" type="radio"><label for="C_H" id="C_H_Label" title="There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.">High (H)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="I_Heading" title="This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.">Integrity (I)</h3>'+
'      <input name="I" value="N" id="I_N" type="radio"><label for="I_N" id="I_N_Label" title="There is no loss of integrity within the impacted component.">None (N)</label>'+
'      <input name="I" value="L" id="I_L" type="radio"><label for="I_L" id="I_L_Label" title="Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is constrained. The data modification does not have a direct, serious impact on the impacted component.">Low (L)</label>'+
'      <input name="I" value="H" id="I_H" type="radio"><label for="I_H" id="I_H_Label" title="There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.">High (H)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="A_Heading" title="This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component.">Availability (A)</h3>'+
'      <input name="A" value="N" id="A_N" type="radio"><label for="A_N" id="A_N_Label" title="There is no impact to availability within the impacted component.">None (N)</label>'+
'      <input name="A" value="L" id="A_L" type="radio"><label for="A_L" id="A_L_Label" title="There is reduced performance or interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.">Low (L)</label>'+
'      <input name="A" value="H" id="A_H" type="radio"><label for="A_H" id="A_H_Label" title="There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).">High (H)</label>'+
'    </div>'+
''+
'  </div>'+
''+
''+
'  <div class="scoreRating">'+
'    <p class="needBaseMetrics">Select values for all base metrics to generate score</p>'+
'    <span id="baseMetricScore"></span>'+
'    <span id="baseSeverity"></span>'+
'  </div>'+
'</fieldset>'+
'<div class="end"></div>'+
''+
'<fieldset style="background: rgba(32, 166, 216, 0.75); color:#ffffff; border-radius:10px">'+
'  <p id="vector">Vector String -'+
'    <span class="needBaseMetrics">select values for all base metrics to generate a vector</span>'+
'    <input id="vectorString" readonly="" type="text">'+
'  </p>'+
'</fieldset>'+
''+
''+
'<fieldset id="temporalMetricGroup">'+
'  <legend id="temporalMetricGroup_Legend" title="The Temporal metrics measure the current state of exploit techniques or code availability, the existence of any patches or workarounds, or the confidence that one has in the description of a vulnerability.">Temporal Score</legend>'+
''+
'  <div class="column column-left">'+
''+
'    <div class="metric">'+
'      <h3 id="E_Heading" title="This metric measures the likelihood of the vulnerability being attacked, and is typically based on the current state of exploit techniques, exploit code availability, or active, \'in-the-wild\' exploitation.">Exploit Code Maturity (E)</h3>'+
'      <input name="E" value="X" id="E_X" checked="" type="radio"><label for="E_X" id="E_X_Label" title="Assigning this value to the metric will not influence the score.">Not Defined (X)</label>'+
'      <input name="E" value="U" id="E_U" type="radio"><label for="E_U" id="E_U_Label" title="No exploit code is available, or an exploit is theoretical.">Unproven (U)</label>'+
'      <input name="E" value="P" id="E_P" type="radio"><label for="E_P" id="E_P_Label" title="Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.">Proof-of-Concept (P)</label>'+
'      <input name="E" value="F" id="E_F" type="radio"><label for="E_F" id="E_F_Label" title="Functional exploit code is available. The code works in most situations where the vulnerability exists.">Functional (F)</label>'+
'      <input name="E" value="H" id="E_H" type="radio"><label for="E_H" id="E_H_Label" title="Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely-available, easy-to-use automated tools.">High (H)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="RL_Heading" title="The Remediation Level of a vulnerability is an important factor for prioritization. The typical vulnerability is unpatched when initially published. Workarounds or hotfixes may offer interim remediation until an official patch or upgrade is issued. Each of these respective stages adjusts the temporal score downwards, reflecting the decreasing urgency as remediation becomes final.">Remediation Level (RL)</h3>'+
'      <input name="RL" value="X" id="RL_X" checked="" type="radio"><label for="RL_X" id="RL_X_Label" title="Assigning this value to the metric will not influence the score.">Not Defined (X)</label>'+
'      <input name="RL" value="O" id="RL_O" type="radio"><label for="RL_O" id="RL_O_Label" title="A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.">Official Fix (O)</label>'+
'      <input name="RL" value="T" id="RL_T" type="radio"><label for="RL_T" id="RL_T_Label" title="There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.">Temporary Fix (T)</label>'+
'      <input name="RL" value="W" id="RL_W" type="radio"><label for="RL_W" id="RL_W_Label" title="There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.">Workaround (W)</label>'+
'      <input name="RL" value="U" id="RL_U" type="radio"><label for="RL_U" id="RL_U_Label" title="There is either no solution available or it is impossible to apply.">Unavailable (U)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="RC_Heading" title="This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details. Sometimes only the existence of vulnerabilities are publicized, but without specific details. For example, an impact may be recognized as undesirable, but the root cause may not be known. The vulnerability may later be corroborated by research which suggests where the vulnerability may lie, though the research may not be certain. Finally, a vulnerability may be confirmed through acknowledgement by the author or vendor of the affected technology. The urgency of a vulnerability is higher when a vulnerability is known to exist with certainty. This metric also suggests the level of technical knowledge available to would-be attackers.">Report Confidence (RC)</h3>'+
'      <input name="RC" value="X" id="RC_X" checked="" type="radio"><label for="RC_X" id="RC_X_Label" title="Assigning this value to the metric will not influence the score.">Not Defined (X)</label>'+
'      <input name="RC" value="U" id="RC_U" type="radio"><label for="RC_U" id="RC_U_Label" title="There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base score can be applied given the differences described. An example is a bug report which notes that an intermittent but non-reproducible crash occurs, with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result.">Unknown (U)</label>'+
'      <input name="RC" value="R" id="RC_R" type="radio"><label for="RC_R" id="RC_R_Label" title="Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (Proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or \'left as an exercise to the reader\') that gives assurances on how to reproduce the results.">Reasonable (R)</label>'+
'      <input name="RC" value="C" id="RC_C" type="radio"><label for="RC_C" id="RC_C_Label" title="Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability.">Confirmed (C)</label>'+
'    </div>'+
''+
'  </div>'+
''+
'  <div class="scoreRating">'+
'    <p class="needBaseMetrics">Select values for all base metrics to generate score</p>'+
'    <span id="temporalMetricScore"></span>'+
'    <span id="temporalSeverity"></span>'+
'  </div>'+
'</fieldset>'+
'<div class="end"></div>'+
''+
''+
''+
'<fieldset id="environmentalMetricGroup">'+
'  <legend id="environmentalMetricGroup_Legend" title="These metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user’s organization, measured in terms of complementary/alternative security controls in place, Confidentiality, Integrity, and Availability. The metrics are the modified equivalent of base metrics and are assigned metric values based on the component placement in organization infrastructure.">Environmental Score</legend>'+
''+
'  <div class="column column-left">'+
''+
'    <div class="metric">'+
'      <h3 id="CR_Heading" title="These metrics enable the analyst to customize the CVSS score depending on the importance of the Confidentiality of the affected IT asset to a user’s organization, relative to other impacts. This metric modifies the environmental score by reweighting the Modified Confidentiality impact metric versus the other modified impacts.">Confidentiality Requirement (CR)</h3>'+
'      <input name="CR" value="X" id="CR_X" checked="" type="radio"><label for="CR_X" id="CR_X_Label" title="Assigning this value to the metric will not influence the score.">Not Defined (X)</label>'+
'      <input name="CR" value="L" id="CR_L" type="radio"><label for="CR_L" id="CR_L_Label" title="Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).">Low (L)</label>'+
'      <input name="CR" value="M" id="CR_M" type="radio"><label for="CR_M" id="CR_M_Label" title="Assigning this value to the metric will not influence the score.">Medium (M)</label>'+
'      <input name="CR" value="H" id="CR_H" type="radio"><label for="CR_H" id="CR_H_Label" title="Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).">High (H)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="IR_Heading" title="These metrics enable the analyst to customize the CVSS score depending on the importance of the Integrity of the affected IT asset to a user’s organization, relative to other impacts. This metric modifies the environmental score by reweighting the Modified Integrity impact metric versus the other modified impacts.">Integrity Requirement (IR)</h3>'+
'      <input name="IR" value="X" id="IR_X" checked="" type="radio"><label for="IR_X" id="IR_X_Label" title="Assigning this value to the metric will not influence the score.">Not Defined (X)</label>'+
'      <input name="IR" value="L" id="IR_L" type="radio"><label for="IR_L" id="IR_L_Label" title="Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).">Low (L)</label>'+
'      <input name="IR" value="M" id="IR_M" type="radio"><label for="IR_M" id="IR_M_Label" title="Assigning this value to the metric will not influence the score.">Medium (M)</label>'+
'      <input name="IR" value="H" id="IR_H" type="radio"><label for="IR_H" id="IR_H_Label" title="Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).">High (H)</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="AR_Heading" title="These metrics enable the analyst to customize the CVSS score depending on the importance of the Availability of the affected IT asset to a user’s organization, relative to other impacts. This metric modifies the environmental score by reweighting the Modified Availability impact metric versus the other modified impacts.">Availability Requirement (AR)</h3>'+
'      <input name="AR" value="X" id="AR_X" checked="" type="radio"><label for="AR_X" id="AR_X_Label" title="Assigning this value to the metric will not influence the score.">Not Defined (X)</label>'+
'      <input name="AR" value="L" id="AR_L" type="radio"><label for="AR_L" id="AR_L_Label" title="Loss of Availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).">Low (L)</label>'+
'      <input name="AR" value="M" id="AR_M" type="radio"><label for="AR_M" id="AR_M_Label" title="Assigning this value to the metric will not influence the score.">Medium (M)</label>'+
'      <input name="AR" value="H" id="AR_H" type="radio"><label for="AR_H" id="AR_H_Label" title="Loss of Availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).">High (H)</label>'+
'    </div>'+
'  </div>'+
''+
'  <div class="column column-right">'+
'    <div class="metric">'+
'      <h3 id="MAV_Heading" title="This metric reflects the context by which vulnerability exploitation is possible. The Base Score increases the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component.">Modified Attack Vector (MAV)</h3>'+
'      <input name="MAV" value="X" id="MAV_X" checked="" type="radio"><label for="MAV_X" id="MAV_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MAV" value="N" id="MAV_N" type="radio"><label for="MAV_N" id="MAV_N_Label" title="A vulnerability exploitable with network access means the vulnerable component is bound to the network stack and the attacker\'s path is through OSI layer 3 (the network layer). Such a vulnerability is often termed "remotely exploitable” and can be thought of as an attack being exploitable one or more network hops away.">Network</label>'+
'      <input name="MAV" value="A" id="MAV_A" type="radio"><label for="MAV_A" id="MAV_A_Label" title="A vulnerability exploitable with adjacent network access means the vulnerable component is bound to the network stack, however the attack is limited to the same shared physical (e.g. Bluetooth, IEEE 802.11), or logical (e.g. local IP subnet) network, and cannot be performed across an OSI layer 3 boundary (e.g. a router).">Adjacent Network</label>'+
'      <input name="MAV" value="L" id="MAV_L" type="radio"><label for="MAV_L" id="MAV_L_Label" title="A vulnerability exploitable with local access means that the vulnerable component is not bound to the network stack, and the attacker’s path is via read/write/execute capabilities. In some cases, the attacker may be logged in locally in order to exploit the vulnerability, otherwise, she may rely on User Interaction to execute a malicious file.">Local</label>'+
'      <input name="MAV" value="P" id="MAV_P" type="radio"><label for="MAV_P" id="MAV_P_Label" title="A vulnerability exploitable with physical access requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent.">Physical</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="MAC_Heading" title="This metric describes the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability. Such conditions may require the collection of more information about the target, the presence of certain system configuration settings, or computational exceptions.">Modified Attack Complexity (MAC)</h3>'+
'      <input name="MAC" value="X" id="MAC_X" checked="" type="radio"><label for="MAC_X" id="MAC_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MAC" value="L" id="MAC_L" type="radio"><label for="MAC_L" id="MAC_L_Label" title="Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component.">Low</label>'+
'      <input name="MAC" value="H" id="MAC_H" type="radio"><label for="MAC_H" id="MAC_H_Label" title="A successful attack depends on conditions beyond the attacker\'s control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may require the attacker: to perform target-specific reconnaissance; to prepare the target environment to improve exploit reliability; or to inject herself into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g. a man in the middle attack).">High</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="MPR_Heading" title="This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. This Base Score increases as fewer privileges are required.">Modified Privileges Required (MPR)</h3>'+
'      <input name="MPR" value="X" id="MPR_X" checked="" type="radio"><label for="MPR_X" id="MPR_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MPR" value="N" id="MPR_N" type="radio"><label for="MPR_N" id="MPR_N_Label" title="The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.">None</label>'+
'      <input name="MPR" value="L" id="MPR_L" type="radio"><label for="MPR_L" id="MPR_L_Label" title="The attacker is authorized with (i.e. requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.">Low</label>'+
'      <input name="MPR" value="H" id="MPR_H" type="radio"><label for="MPR_H" id="MPR_H_Label" title="The attacker is authorized with (i.e. requires) privileges that provide significant (e.g. administrative) control over the vulnerable component that could affect component-wide settings and files.">High</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="MUI_Heading" title="This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner. The Base Score is highest when no user interaction is required.">Modified User Interaction (MUI)</h3>'+
'      <input name="MUI" value="X" id="MUI_X" checked="" type="radio"><label for="MUI_X" id="MUI_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MUI" value="N" id="MUI_N" type="radio"><label for="MUI_N" id="MUI_N_Label" title="The vulnerable system can be exploited without any interaction from any user.">None</label>'+
'      <input name="MUI" value="R" id="MUI_R" type="radio"><label for="MUI_R" id="MUI_R_Label" title="Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.">Required</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="MS_Heading" title="Does a successful attack impact a component other than the vulnerable component? If so, the Base Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.">Modified Scope (MS)</h3>'+
'      <input name="MS" value="X" id="MS_X" checked="" type="radio"><label for="MS_X" id="MS_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MS" value="U" id="MS_U" type="radio"><label for="MS_U" id="MS_U_Label" title="An exploited vulnerability can only affect resources managed by the same authority. In this case the vulnerable component and the impacted component are the same.">Unchanged</label>'+
'      <input name="MS" value="C" id="MS_C" type="radio"><label for="MS_C" id="MS_C_Label" title="An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component. In this case the vulnerable component and the impacted component are different.">Changed</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="MC_Heading" title="This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.">Modified Confidentiality (MC)</h3>'+
'      <input name="MC" value="X" id="MC_X" checked="" type="radio"><label for="MC_X" id="MC_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MC" value="N" id="MC_N" type="radio"><label for="MC_N" id="MC_N_Label" title="There is no loss of confidentiality within the impacted component.">None</label>'+
'      <input name="MC" value="L" id="MC_L" type="radio"><label for="MC_L" id="MC_L_Label" title="There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is constrained. The information disclosure does not cause a direct, serious loss to the impacted component.">Low</label>'+
'      <input name="MC" value="H" id="MC_H" type="radio"><label for="MC_H" id="MC_H_Label" title="There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.">High</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="MI_Heading" title="This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.">Modified Integrity (MI)</h3>'+
'      <input name="MI" value="X" id="MI_X" checked="" type="radio"><label for="MI_X" id="MI_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MI" value="N" id="MI_N" type="radio"><label for="MI_N" id="MI_N_Label" title="There is no loss of integrity within the impacted component.">None</label>'+
'      <input name="MI" value="L" id="MI_L" type="radio"><label for="MI_L" id="MI_L_Label" title="Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is constrained. The data modification does not have a direct, serious impact on the impacted component.">Low</label>'+
'      <input name="MI" value="H" id="MI_H" type="radio"><label for="MI_H" id="MI_H_Label" title="There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.">High</label>'+
'    </div>'+
''+
'    <div class="metric">'+
'      <h3 id="MA_Heading" title="This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component.">Modified Availability (MA)</h3>'+
'      <input name="MA" value="X" id="MA_X" checked="" type="radio"><label for="MA_X" id="MA_X_Label" title="Use the value assigned to the corresponding Base Score metric.">Not Defined (X)</label>'+
'      <input name="MA" value="N" id="MA_N" type="radio"><label for="MA_N" id="MA_N_Label" title="There is no impact to availability within the impacted component.">None</label>'+
'      <input name="MA" value="L" id="MA_L" type="radio"><label for="MA_L" id="MA_L_Label" title="There is reduced performance or interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.">Low</label>'+
'      <input name="MA" value="H" id="MA_H" type="radio"><label for="MA_H" id="MA_H_Label" title="There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).">High</label>'+
'    </div>'+
'  </div>'+
''+
'  <div class="scoreRating">'+
'    <p class="needBaseMetrics">Select values for all base metrics to generate score</p>'+
'    <span id="environmentalMetricScore"></span>'+
'    <span id="environmentalSeverity"></span>'+
'  </div>'+
'</fieldset>'+
'<div class="end"></div>'+
''+
'</form>'+
'<!-- CVSS Calculator end -->';

$(".cvsscalculator").parent().append(response);
  $(document).ready(function() {
    $("#id_cvssv3").click(function(){
      $("#cvsscalculator").toggle();
  });
});

$(document).mouseup(function (e){
	var container = $("#cvsscalculator");
	if (!container.is(e.target) && container.has(e.target).length === 0){
		container.hide();
	}
});

"use strict";

function updateScores() {
    var result = CVSS.calculateCVSSFromMetrics(inputValue('input[type="radio"][name=AV]:checked'), inputValue('input[type="radio"][name=AC]:checked'), inputValue('input[type="radio"][name=PR]:checked'), inputValue('input[type="radio"][name=UI]:checked'), inputValue('input[type="radio"][name=S]:checked'), inputValue('input[type="radio"][name=C]:checked'), inputValue('input[type="radio"][name=I]:checked'), inputValue('input[type="radio"][name=A]:checked'), inputValue('input[type="radio"][name=E]:checked'), inputValue('input[type="radio"][name=RL]:checked'), inputValue('input[type="radio"][name=RC]:checked'), inputValue('input[type="radio"][name=CR]:checked'), inputValue('input[type="radio"][name=IR]:checked'), inputValue('input[type="radio"][name=AR]:checked'), inputValue('input[type="radio"][name=MAV]:checked'), inputValue('input[type="radio"][name=MAC]:checked'), inputValue('input[type="radio"][name=MPR]:checked'), inputValue('input[type="radio"][name=MUI]:checked'), inputValue('input[type="radio"][name=MS]:checked'), inputValue('input[type="radio"][name=MC]:checked'), inputValue('input[type="radio"][name=MI]:checked'), inputValue('input[type="radio"][name=MA]:checked'));
    if (result.success === true) {
        var L = document.querySelectorAll(".needBaseMetrics"),
            i = L.length;
        while (i--) {
            hide(L[i])
        }
        parentNode(text("#baseMetricScore", result.baseMetricScore), ".scoreRating").className = "scoreRating " + result.baseSeverity.toLowerCase();
        text("#baseSeverity", "(" + result.baseSeverity + ")");
        parentNode(text("#temporalMetricScore", result.temporalMetricScore), ".scoreRating").className = "scoreRating " + result.temporalSeverity.toLowerCase();
        text("#temporalSeverity", "(" + result.temporalSeverity + ")");
        parentNode(text("#environmentalMetricScore", result.environmentalMetricScore), ".scoreRating").className = "scoreRating " + result.environmentalSeverity.toLowerCase();
        text("#environmentalSeverity", "(" + result.environmentalSeverity + ")");
        show(inputValue("#vectorString", result.vectorString));
        document.getElementById("id_cvssv3").value = result.vectorString;
        if (result.environmentalSeverity != 'None'){
            document.getElementById("id_severity").value = result.environmentalSeverity;
        }
        else{
            document.getElementById("id_severity").value = 'Info'
        };

    } else {
        if (result.error === "Not all base metrics were given - cannot calculate scores.") {
            var L = document.querySelectorAll(".needBaseMetrics"),
                i = L.length;
            while (i--) {
                show(L[i])
            }
            hide("#vectorString")
        }
    }
}

function delayedUpdateScores() {
    setTimeout(updateScores, 100)
}
window.Element && function (ElementPrototype) {
    ElementPrototype.matchesSelector = ElementPrototype.matchesSelector || ElementPrototype.mozMatchesSelector || ElementPrototype.msMatchesSelector || ElementPrototype.oMatchesSelector || ElementPrototype.webkitMatchesSelector || function (selector) {
        var node = this,
            nodes = (node.parentNode || node.document).querySelectorAll(selector),
            i = -1;
        while (nodes[++i] && nodes[i] != node) {}
        return !!nodes[i]
    }
}(Element.prototype);
var matchesSelector = function (node, selector) {
    if (!("parentNode" in node) || !node.parentNode) {
        return false
    }
    return Array.prototype.indexOf.call(node.parentNode.querySelectorAll(selector)) != -1
};

function node() {
    for (var i = 0; i < arguments.length; i++) {
        var o = arguments[i];
        if (typeof (o) == "string" && o) {
            return document.querySelector(o)
        } else {
            if ("nodeName" in o) {
                return o
            } else {
                if ("jquery" in o) {
                    return o.get(0)
                }
            }
        }
    }
    return false
}

function parentNode(p, q) {
    if (!p || !(p = node(p))) {
        return
    } else {
        if ((typeof (q) == "string" && p.matchesSelector(q)) || p == q) {
            return p
        } else {
            if (p.nodeName.toLowerCase() != "html") {
                return parentNode(p.parentNode, q)
            } else {
                return
            }
        }
    }
}

function bind(q, tg, fn) {
    var o = node(q);
    if (!o) {
        return
    }
    if (o.addEventListener) {
        o.addEventListener(tg, fn, false)
    } else {
        if (o.attachEvent) {
            o.attachEvent("on" + tg, fn)
        } else {
            o["on" + tg] = fn
        }
    }
    return o
}

function text(q, s) {
    var e = node(q);
    if (!e) {
        return
    }
    if (arguments.length > 1) {
        if ("textContent" in e) {
            e.textContent = s
        } else {
            e.innerText = s
        }
        return e
    }
    return e.textContent || e.innerText
}

function hide(q) {
    var e = node(q);
    if (!e) {
        return
    }
    e.setAttribute("style", "display:none");
    return e
}

function show(q) {
    var e = node(q);
    if (!e) {
        return
    }
    e.setAttribute("style", "display:inline-block");
    return e
}

function inputValue(q, v) {
    var e = document.querySelector(q);
    if (!e || e.nodeName.toLowerCase() != "input") {
        return
    }
    if (arguments.length > 1) {
        e.value = v;
        return e
    }
    return e.value
}

function setMetricsFromVector(vectorString) {
    var result = true;
    var urlMetric;
    var metricValuesToSet = {
        AV: undefined,
        AC: undefined,
        PR: undefined,
        UI: undefined,
        S: undefined,
        C: undefined,
        I: undefined,
        A: undefined,
        E: "X",
        RL: "X",
        RC: "X",
        CR: "X",
        IR: "X",
        AR: "X",
        MAV: "X",
        MAC: "X",
        MPR: "X",
        MUI: "X",
        MS: "X",
        MC: "X",
        MI: "X",
        MA: "X"
    };
    var vectorStringRegex_30 = /^CVSS:3.0\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/;
    if (vectorStringRegex_30.test(vectorString)) {
        var urlMetrics = vectorString.substring("CVSS:3.0/".length).split("/");
        for (var p in urlMetrics) {
            var urlMetric = urlMetrics[p].split(":");
            metricValuesToSet[urlMetric[0]] = urlMetric[1]
        }
        if (metricValuesToSet.AV !== undefined && metricValuesToSet.AC !== undefined && metricValuesToSet.PR !== undefined && metricValuesToSet.UI !== undefined && metricValuesToSet.S !== undefined && metricValuesToSet.C !== undefined && metricValuesToSet.I !== undefined && metricValuesToSet.A !== undefined) {
            for (var p in metricValuesToSet) {
                document.getElementById(p + "_" + metricValuesToSet[p]).checked = true
            }
        } else {
            result = "NotAllBaseMetricsProvided"
        }
    } else {
        result = "MalformedVectorString"
    }
    updateScores();
    return result
}
var CVSSVectorInURL;

function urlhash() {
    var h = document.getElementById("id_cvssv3").value;
    CVSSVectorInURL = h;
    setMetricsFromVector(h)
}

function inputSelect() {
    this.setSelectionRange(0, this.value.length)
}

function cvssCalculator() {
    if (!("CVSS" in window) || !("CVSS_Help" in window )) {
        setTimeout(cvssCalculator, 100);
        return
    }
    var L, i, n;
    L = document.querySelectorAll("#cvsscalculator input");
    i = L.length;
    while (i--) {
        bind(L[i], "click", delayedUpdateScores)
    }
    for (n in CVSS_Help.helpText_en) {
        document.getElementById(n).setAttribute("title", CVSS_Help.helpText_en[n])
    }
    urlhash();
    if (("onhashchange" in window)) {
        window.onhashchange = urlhash
    }
    bind(bind("#vectorString", "click", inputSelect), "contextmenu", inputSelect)
}
if ((document.getElementById("id_cvssv3")) && (document.getElementById("cvsscalculator"))) {
    cvssCalculator();
}