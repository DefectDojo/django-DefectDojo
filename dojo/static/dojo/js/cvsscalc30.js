/* Copyright (c) 2015, FIRST.ORG, INC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This JavaScript contains two main functions. Both take CVSS metric values and calculate CVSS scores for Base,
 * Temporal and Environmental metric groups, their associated severity ratings, and an overall Vector String.
 *
 * Use CVSS.calculateCVSSFromMetrics if you wish to pass metric values as individual parameters.
 * Use CVSS.calculateCVSSFromVector if you wish to pass metric values as a single Vector String.
 *
 * Changelog
 *
 * 2018-02-15  Darius Wiles   Added a missing pair of parantheses in the Environmental score, specifically
 *                            in the code setting envScore in the main clause (not the else clause). It was changed
 *                            from "min (...), 10" to "min ((...), 10)". This correction does not alter any final
 *                            Environmental scores.
 *
 * 2015-08-04  Darius Wiles   Added CVSS.generateXMLFromMetrics and CVSS.generateXMLFromVector functions to return
 *                            XML string representations of: a set of metric values; or a Vector String respectively.
 *                            Moved all constants and functions to an object named "CVSS" to
 *                            reduce the chance of conflicts in global variables when this file is combined with
 *                            other JavaScript code. This will break all existing code that uses this file until
 *                            the string "CVSS." is prepended to all references. The "Exploitability" metric has been
 *                            renamed "Exploit Code Maturity" in the specification, so the same change has been made
 *                            in the code in this file.
 *
 * 2015-04-24  Darius Wiles   Environmental formula modified to eliminate undesirable behavior caused by subtle
 *                            differences in rounding between Temporal and Environmental formulas that often
 *                            caused the latter to be 0.1 lower than than the former when all Environmental
 *                            metrics are "Not defined". Also added a RoundUp1 function to simplify formulas.
 *
 * 2015-04-09  Darius Wiles   Added calculateCVSSFromVector function, license information, cleaned up code and improved
 *                            comments.
 *
 * 2014-12-12  Darius Wiles   Initial release for CVSS 3.0 Preview 2.
 */

// Constants used in the formula. They are not declared as "const" to avoid problems in older browsers.

var CVSS = {};

CVSS.CVSSVersionIdentifier = "CVSS:3.0";
CVSS.exploitabilityCoefficient = 8.22;
CVSS.scopeCoefficient = 1.08;

// A regular expression to validate that a CVSS 3.0 vector string is well formed. It checks metrics and metric
// values. It does not check that a metric is specified more than once and it does not check that all base
// metrics are present. These checks need to be performed separately.

CVSS.vectorStringRegex_30 = /^CVSS:3\.0\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/;


// Associative arrays mapping each metric value to the constant defined in the CVSS scoring formula in the CVSS v3.0
// specification.

CVSS.Weight = {
  AV:   { N: 0.85,  A: 0.62,  L: 0.55,  P: 0.2},
  AC:   { H: 0.44,  L: 0.77},
  PR:   { U:       {N: 0.85,  L: 0.62,  H: 0.27},         // These values are used if Scope is Unchanged
          C:       {N: 0.85,  L: 0.68,  H: 0.5}},         // These values are used if Scope is Changed
  UI:   { N: 0.85,  R: 0.62},
  S:    { U: 6.42,  C: 7.52},                             // Note: not defined as constants in specification
  CIA:  { N: 0,     L: 0.22,  H: 0.56},                   // C, I and A have the same weights

  E:    { X: 1,     U: 0.91,  P: 0.94,  F: 0.97,  H: 1},
  RL:   { X: 1,     O: 0.95,  T: 0.96,  W: 0.97,  U: 1},
  RC:   { X: 1,     U: 0.92,  R: 0.96,  C: 1},

  CIAR: { X: 1,     L: 0.5,   M: 1,     H: 1.5}           // CR, IR and AR have the same weights
};


// Severity rating bands, as defined in the CVSS v3.0 specification.

CVSS.severityRatings  = [ { name: "None",     bottom: 0.0, top:  0.0},
                          { name: "Low",      bottom: 0.1, top:  3.9},
                          { name: "Medium",   bottom: 4.0, top:  6.9},
                          { name: "High",     bottom: 7.0, top:  8.9},
                          { name: "Critical", bottom: 9.0, top: 10.0} ];




/* ** CVSS.calculateCVSSFromMetrics **
 *
 * Takes Base, Temporal and Environmental metric values as individual parameters. Their values are in the short format
 * defined in the CVSS v3.0 standard definition of the Vector String. For example, the AttackComplexity parameter
 * should be either "H" or "L".
 *
 * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
 * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
 * passed default to "X" ("Not Defined").
 *
 * The output is an object which always has a property named "success".
 *
 * If no errors are encountered, success is Boolean "true", and the following other properties are defined containing
 * scores, severities and a vector string:
 *   baseMetricScore, baseSeverity,
 *   temporalMetricScore, temporalSeverity,
 *   environmentalMetricScore, environmentalSeverity,
 *   vectorString
 *
 * If errors are encountered, success is Boolean "false", and the following other properties are defined:
 *   errorType - a string indicating the error. Either:
 *                 "MissingBaseMetric", if at least one Base metric has not been defined; or
 *                 "UnknownMetricValue", if at least one metric value is invalid.
 *   errorMetrics - an array of strings representing the metrics at fault. The strings are abbreviated versions of the
 *                  metrics, as defined in the CVSS v3.0 standard definition of the Vector String.
 */
CVSS.calculateCVSSFromMetrics = function (
  AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Confidentiality, Integrity, Availability,
  ExploitCodeMaturity, RemediationLevel, ReportConfidence,
  ConfidentialityRequirement, IntegrityRequirement, AvailabilityRequirement,
  ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope,
  ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability) {

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];

  // ENSURE ALL BASE METRICS ARE DEFINED
  //
  // We need values for all Base Score metrics to calculate scores.
  // If any Base Score parameters are undefined, create an array of missing metrics and return it with an error.

  if (typeof AttackVector       === "undefined" || AttackVector       === "") { badMetrics.push("AV"); }
  if (typeof AttackComplexity   === "undefined" || AttackComplexity   === "") { badMetrics.push("AC"); }
  if (typeof PrivilegesRequired === "undefined" || PrivilegesRequired === "") { badMetrics.push("PR"); }
  if (typeof UserInteraction    === "undefined" || UserInteraction    === "") { badMetrics.push("UI"); }
  if (typeof Scope              === "undefined" || Scope              === "") { badMetrics.push("S");  }
  if (typeof Confidentiality    === "undefined" || Confidentiality    === "") { badMetrics.push("C");  }
  if (typeof Integrity          === "undefined" || Integrity          === "") { badMetrics.push("I");  }
  if (typeof Availability       === "undefined" || Availability       === "") { badMetrics.push("A");  }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MissingBaseMetric", errorMetrics: badMetrics };
  }


  // STORE THE METRIC VALUES THAT WERE PASSED AS PARAMETERS
  //
  // Temporal and Environmental metrics are optional, so set them to "X" ("Not Defined") if no value was passed.

  var AV = AttackVector;
  var AC = AttackComplexity;
  var PR = PrivilegesRequired;
  var UI = UserInteraction;
  var S  = Scope;
  var C  = Confidentiality;
  var I  = Integrity;
  var A  = Availability;

  var E =   ExploitCodeMaturity || "X";
  var RL =  RemediationLevel    || "X";
  var RC =  ReportConfidence    || "X";

  var CR =  ConfidentialityRequirement || "X";
  var IR =  IntegrityRequirement       || "X";
  var AR =  AvailabilityRequirement    || "X";
  var MAV = ModifiedAttackVector       || "X";
  var MAC = ModifiedAttackComplexity   || "X";
  var MPR = ModifiedPrivilegesRequired || "X";
  var MUI = ModifiedUserInteraction    || "X";
  var MS =  ModifiedScope              || "X";
  var MC =  ModifiedConfidentiality    || "X";
  var MI =  ModifiedIntegrity          || "X";
  var MA =  ModifiedAvailability       || "X";


  // CHECK VALIDITY OF METRIC VALUES
  //
  // Use the Weight object to ensure that, for every metric, the metric value passed is valid.
  // If any invalid values are found, create an array of their metrics and return it with an error.
  //
  // The Privileges Required (PR) weight depends on Scope, but when checking the validity of PR we must not assume
  // that the given value for Scope is valid. We therefore always look at the weights for Unchanged Scope when
  // performing this check. The same applies for validation of Modified Privileges Required (MPR).
  //
  // The Weights object does not contain "X" ("Not Defined") values for Environmental metrics because we replace them
  // with their Base metric equivalents later in the function. For example, an MAV of "X" will be replaced with the
  // value given for AV. We therefore need to explicitly allow a value of "X" for Environmental metrics.

  if (!CVSS.Weight.AV.hasOwnProperty(AV))   { badMetrics.push("AV"); }
  if (!CVSS.Weight.AC.hasOwnProperty(AC))   { badMetrics.push("AC"); }
  if (!CVSS.Weight.PR.U.hasOwnProperty(PR)) { badMetrics.push("PR"); }
  if (!CVSS.Weight.UI.hasOwnProperty(UI))   { badMetrics.push("UI"); }
  if (!CVSS.Weight.S.hasOwnProperty(S))     { badMetrics.push("S"); }
  if (!CVSS.Weight.CIA.hasOwnProperty(C))   { badMetrics.push("C"); }
  if (!CVSS.Weight.CIA.hasOwnProperty(I))   { badMetrics.push("I"); }
  if (!CVSS.Weight.CIA.hasOwnProperty(A))   { badMetrics.push("A"); }

  if (!CVSS.Weight.E.hasOwnProperty(E))     { badMetrics.push("E"); }
  if (!CVSS.Weight.RL.hasOwnProperty(RL))   { badMetrics.push("RL"); }
  if (!CVSS.Weight.RC.hasOwnProperty(RC))   { badMetrics.push("RC"); }

  if (!(CR  === "X" || CVSS.Weight.CIAR.hasOwnProperty(CR)))  { badMetrics.push("CR"); }
  if (!(IR  === "X" || CVSS.Weight.CIAR.hasOwnProperty(IR)))  { badMetrics.push("IR"); }
  if (!(AR  === "X" || CVSS.Weight.CIAR.hasOwnProperty(AR)))  { badMetrics.push("AR"); }
  if (!(MAV === "X" || CVSS.Weight.AV.hasOwnProperty(MAV)))   { badMetrics.push("MAV"); }
  if (!(MAC === "X" || CVSS.Weight.AC.hasOwnProperty(MAC)))   { badMetrics.push("MAC"); }
  if (!(MPR === "X" || CVSS.Weight.PR.U.hasOwnProperty(MPR))) { badMetrics.push("MPR"); }
  if (!(MUI === "X" || CVSS.Weight.UI.hasOwnProperty(MUI)))   { badMetrics.push("MUI"); }
  if (!(MS  === "X" || CVSS.Weight.S.hasOwnProperty(MS)))     { badMetrics.push("MS"); }
  if (!(MC  === "X" || CVSS.Weight.CIA.hasOwnProperty(MC)))   { badMetrics.push("MC"); }
  if (!(MI  === "X" || CVSS.Weight.CIA.hasOwnProperty(MI)))   { badMetrics.push("MI"); }
  if (!(MA  === "X" || CVSS.Weight.CIA.hasOwnProperty(MA)))   { badMetrics.push("MA"); }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "UnknownMetricValue", errorMetrics: badMetrics };
  }



  // GATHER WEIGHTS FOR ALL METRICS

  var metricWeightAV  = CVSS.Weight.AV    [AV];
  var metricWeightAC  = CVSS.Weight.AC    [AC];
  var metricWeightPR  = CVSS.Weight.PR    [S][PR];  // PR depends on the value of Scope (S).
  var metricWeightUI  = CVSS.Weight.UI    [UI];
  var metricWeightS   = CVSS.Weight.S     [S];
  var metricWeightC   = CVSS.Weight.CIA   [C];
  var metricWeightI   = CVSS.Weight.CIA   [I];
  var metricWeightA   = CVSS.Weight.CIA   [A];

  var metricWeightE   = CVSS.Weight.E     [E];
  var metricWeightRL  = CVSS.Weight.RL    [RL];
  var metricWeightRC  = CVSS.Weight.RC    [RC];

  // For metrics that are modified versions of Base Score metrics, e.g. Modified Attack Vector, use the value of
  // the Base Score metric if the modified version value is "X" ("Not Defined").
  var metricWeightCR  = CVSS.Weight.CIAR  [CR];
  var metricWeightIR  = CVSS.Weight.CIAR  [IR];
  var metricWeightAR  = CVSS.Weight.CIAR  [AR];
  var metricWeightMAV = CVSS.Weight.AV    [MAV !== "X" ? MAV : AV];
  var metricWeightMAC = CVSS.Weight.AC    [MAC !== "X" ? MAC : AC];
  var metricWeightMPR = CVSS.Weight.PR    [MS  !== "X" ? MS  : S] [MPR !== "X" ? MPR : PR];  // Depends on MS.
  var metricWeightMUI = CVSS.Weight.UI    [MUI !== "X" ? MUI : UI];
  var metricWeightMS  = CVSS.Weight.S     [MS  !== "X" ? MS  : S];
  var metricWeightMC  = CVSS.Weight.CIA   [MC  !== "X" ? MC  : C];
  var metricWeightMI  = CVSS.Weight.CIA   [MI  !== "X" ? MI  : I];
  var metricWeightMA  = CVSS.Weight.CIA   [MA  !== "X" ? MA  : A];



  // CALCULATE THE CVSS BASE SCORE

  var baseScore;
  var impactSubScore;
  var exploitabalitySubScore = CVSS.exploitabilityCoefficient * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI;
  var impactSubScoreMultiplier = (1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA)));

  if (S === 'U') {
    impactSubScore = metricWeightS * impactSubScoreMultiplier;
  } else {
    impactSubScore = metricWeightS * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
  }

  if (impactSubScore <= 0) {
    baseScore = 0;
  } else {
    if (S === 'U') {
      baseScore = CVSS.roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10));
    } else {
      baseScore = CVSS.roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * CVSS.scopeCoefficient, 10));
    }
  }



  // CALCULATE THE CVSS TEMPORAL SCORE

  var temporalScore = CVSS.roundUp1(baseScore * metricWeightE * metricWeightRL * metricWeightRC);


  // CALCULATE THE CVSS ENVIRONMENTAL SCORE
  //
  // - envExploitabalitySubScore recalculates the Base Score Exploitability sub-score using any modified values from the
  //   Environmental metrics group in place of the values specified in the Base Score, if any have been defined.
  // - envAdjustedImpactSubScore recalculates the Base Score Impact sub-score using any modified values from the
  //   Environmental metrics group in place of the values specified in the Base Score, and any additional weightings
  //   given in the Environmental metrics group.

  var envScore;
  var envModifiedImpactSubScore;
  var envModifiedExploitabalitySubScore = CVSS.exploitabilityCoefficient * metricWeightMAV * metricWeightMAC * metricWeightMPR * metricWeightMUI;

  var envImpactSubScoreMultiplier = Math.min (1 - (
                                               (1 - metricWeightMC * metricWeightCR) *
                                               (1 - metricWeightMI * metricWeightIR) *
                                               (1 - metricWeightMA * metricWeightAR)), 0.915);

  if (MS === "U" ||
     (MS === "X" && S === "U")) {
    envModifiedImpactSubScore = metricWeightMS * envImpactSubScoreMultiplier;
    envScore = CVSS.roundUp1(CVSS.roundUp1(Math.min((envModifiedImpactSubScore + envModifiedExploitabalitySubScore), 10)) *
                        metricWeightE * metricWeightRL * metricWeightRC);
    } else {
    envModifiedImpactSubScore = metricWeightMS * (envImpactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(envImpactSubScoreMultiplier - 0.02, 15);
    envScore = CVSS.roundUp1(CVSS.roundUp1(Math.min(CVSS.scopeCoefficient * (envModifiedImpactSubScore + envModifiedExploitabalitySubScore), 10)) *
                        metricWeightE * metricWeightRL * metricWeightRC);
  }

  if (envModifiedImpactSubScore <= 0) {
    envScore = 0;
  }


  // CONSTRUCT THE VECTOR STRING

  var vectorString =
    CVSS.CVSSVersionIdentifier +
    "/AV:" + AV +
    "/AC:" + AC +
    "/PR:" + PR +
    "/UI:" + UI +
    "/S:"  + S +
    "/C:"  + C +
    "/I:"  + I +
    "/A:"  + A;

  if (E  !== "X")  {vectorString = vectorString + "/E:" + E;}
  if (RL !== "X")  {vectorString = vectorString + "/RL:" + RL;}
  if (RC !== "X")  {vectorString = vectorString + "/RC:" + RC;}

  if (CR  !== "X") {vectorString = vectorString + "/CR:" + CR;}
  if (IR  !== "X") {vectorString = vectorString + "/IR:"  + IR;}
  if (AR  !== "X") {vectorString = vectorString + "/AR:"  + AR;}
  if (MAV !== "X") {vectorString = vectorString + "/MAV:" + MAV;}
  if (MAC !== "X") {vectorString = vectorString + "/MAC:" + MAC;}
  if (MPR !== "X") {vectorString = vectorString + "/MPR:" + MPR;}
  if (MUI !== "X") {vectorString = vectorString + "/MUI:" + MUI;}
  if (MS  !== "X") {vectorString = vectorString + "/MS:"  + MS;}
  if (MC  !== "X") {vectorString = vectorString + "/MC:"  + MC;}
  if (MI  !== "X") {vectorString = vectorString + "/MI:"  + MI;}
  if (MA  !== "X") {vectorString = vectorString + "/MA:"  + MA;}


  // Return an object containing the scores for all three metric groups, and an overall vector string.

  return {
    success: true,
    baseMetricScore: baseScore.toFixed(1),
    baseSeverity: CVSS.severityRating( baseScore.toFixed(1) ),

    temporalMetricScore: temporalScore.toFixed(1),
    temporalSeverity: CVSS.severityRating( temporalScore.toFixed(1) ),

    environmentalMetricScore: envScore.toFixed(1),
    environmentalSeverity: CVSS.severityRating( envScore.toFixed(1) ),

    vectorString: vectorString
  };
};




/* ** CVSS.calculateCVSSFromVector **
 *
 * Takes Base, Temporal and Environmental metric values as a single string in the Vector String format defined
 * in the CVSS v3.0 standard definition of the Vector String.
 *
 * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
 * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
 * passed default to "X" ("Not Defined").
 *
 * See the comment for the CVSS.calculateCVSSFromMetrics function for details on the function output. In addition to
 * the error conditions listed for that function, this function can also return:
 *   "MalformedVectorString", if the Vector String passed is does not conform to the format in the standard; or
 *   "MultipleDefinitionsOfMetric", if the Vector String is well formed but defines the same metric (or metrics),
 *                                  more than once.
 */
CVSS.calculateCVSSFromVector = function ( vectorString ) {

  var metricValues = {
    AV:  undefined, AC:  undefined, PR:  undefined, UI:  undefined, S:  undefined,
    C:   undefined, I:   undefined, A:   undefined,
    E:   undefined, RL:  undefined, RC:  undefined,
    CR:  undefined, IR:  undefined, AR:  undefined,
    MAV: undefined, MAC: undefined, MPR: undefined, MUI: undefined, MS: undefined,
    MC:  undefined, MI:  undefined, MA:  undefined
  };

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];

  if (!CVSS.vectorStringRegex_30.test(vectorString)) {
    return { success: false, errorType: "MalformedVectorString" };
  }

  var metricNameValue = vectorString.substring(CVSS.CVSSVersionIdentifier.length).split("/");

  for (var i in metricNameValue) {
    if (metricNameValue.hasOwnProperty(i)) {

      var singleMetric = metricNameValue[i].split(":");

      if (typeof metricValues[singleMetric[0]] === "undefined") {
        metricValues[singleMetric[0]] = singleMetric[1];
      } else {
        badMetrics.push(singleMetric[0]);
      }
    }
  }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MultipleDefinitionsOfMetric", errorMetrics: badMetrics };
  }

  return CVSS.calculateCVSSFromMetrics (
    metricValues.AV,  metricValues.AC,  metricValues.PR,  metricValues.UI,  metricValues.S,
    metricValues.C,   metricValues.I,   metricValues.A,
    metricValues.E,   metricValues.RL,  metricValues.RC,
    metricValues.CR,  metricValues.IR,  metricValues.AR,
    metricValues.MAV, metricValues.MAC, metricValues.MPR, metricValues.MUI, metricValues.MS,
    metricValues.MC,  metricValues.MI,  metricValues.MA);
};




/* ** CVSS.roundUp1 **
 *
 * Rounds up the number passed as a parameter to 1 decimal place and returns the result.
 *
 * Standard JavaScript errors thrown when arithmetic operations are performed on non-numbers will be returned if the
 * given input is not a number.
 */
CVSS.roundUp1 = function (d) {
  return Math.ceil (d * 10) / 10;
};




/* ** CVSS.severityRating **
 *
 * Given a CVSS score, returns the name of the severity rating as defined in the CVSS standard.
 * The input needs to be a number between 0.0 to 10.0, to one decimal place of precision.
 *
 * The following error values may be returned instead of a severity rating name:
 *   NaN (JavaScript "Not a Number") - if the input is not a number.
 *   undefined - if the input is a number that is not within the range of any defined severity rating.
 */
CVSS.severityRating = function (score) {
  var severityRatingLength = CVSS.severityRatings.length;

  var validatedScore = Number(score);

  if (isNaN(validatedScore)) {
    return validatedScore;
  }

  for (var i = 0; i < severityRatingLength; i++) {
    if (score >= CVSS.severityRatings[i].bottom && score <= CVSS.severityRatings[i].top) {
      return CVSS.severityRatings[i].name;
    }
  }

  return undefined;
};



///////////////////////////////////////////////////////////////////////////
// DATA AND FUNCTIONS FOR CREATING AN XML REPRESENTATION OF A CVSS SCORE //
///////////////////////////////////////////////////////////////////////////

// A mapping between abbreviated metric values and the string used in the XML representation.
// For example, a Remediation Level (RL) abbreviated metric value of "W" maps to "WORKAROUND".
// For brevity, Base metric values their modified equivalents in the Environmental metric group. We can do this
// because the latter is the same as the former, except it also includes a "NOT_DEFINED" value.

CVSS.XML_MetricNames = {
  E:    { X: "NOT_DEFINED", U: "UNPROVEN",     P: "PROOF_OF_CONCEPT",  F: "FUNCTIONAL",  H: "HIGH"},
  RL:   { X: "NOT_DEFINED", O: "OFFICIAL_FIX", T: "TEMPORARY_FIX",     W: "WORKAROUND",  U: "UNAVAILABLE"},
  RC:   { X: "NOT_DEFINED", U: "UNKNOWN",      R: "REASONABLE",        C: "CONFIRMED"},

  CIAR: { X: "NOT_DEFINED", L: "LOW",              M: "MEDIUM", H: "HIGH"},         // CR, IR and AR use the same metric names
  MAV:  { N: "NETWORK",     A: "ADJACENT_NETWORK", L: "LOCAL",  P: "PHYSICAL", X: "NOT_DEFINED" },
  MAC:  { H: "HIGH",        L: "LOW",              X: "NOT_DEFINED" },
  MPR:  { N: "NONE",        L: "LOW",              H: "HIGH",   X: "NOT_DEFINED" },
  MUI:  { N: "NONE",        R: "REQUIRED",         X: "NOT_DEFINED" },
  MS:   { U: "UNCHANGED",   C: "CHANGED",          X: "NOT_DEFINED" },
  MCIA: { N: "NONE",        L: "LOW",              H: "HIGH",   X: "NOT_DEFINED" }  // C, I and A use the same metric names
};



/* ** CVSS.generateXMLFromMetrics **
 *
 * Takes Base, Temporal and Environmental metric values as individual parameters. Their values are in the short format
 * defined in the CVSS v3.0 standard definition of the Vector String. For example, the AttackComplexity parameter
 * should be either "H" or "L".
 *
 * Returns a single string containing the metric values in XML form. All Base metrics are required to generate this
 * output. All Temporal and Environmental metric values are optional. Any that are not passed will be represented in
 * the XML as NOT_DEFINED. The function returns a string for simplicity. It is arguably better to return the XML as
 * a DOM object, but at the time of writing this leads to complexity due to older browsers using different JavaScript
 * interfaces to do this. Also for simplicity, all Temporal and Environmental metrics are include in the string,
 * even though those with a value of "Not Defined" do not need to be included.
 *
 * The output of this function is an object which always has a property named "success".
 *
 * If no errors are encountered, success is Boolean "true", and the "xmlString" property contains the XML string
 * representation.
 *
 * If errors are encountered, success is Boolean "false", and other properties are defined as per the
 * CVSS.calculateCVSSFromMetrics function. Refer to the comment for that function for more details.
 */
CVSS.generateXMLFromMetrics = function (
  AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Confidentiality, Integrity, Availability,
  ExploitCodeMaturity, RemediationLevel, ReportConfidence,
  ConfidentialityRequirement, IntegrityRequirement, AvailabilityRequirement,
  ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope,
  ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability) {

  // A string containing the XML we wish to output, with placeholders for the CVSS metrics we will substitute for
  // their values, based on the inputs passed to this function.
  var xmlTemplate =
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<cvssv3.0 xmlns="https://www.first.org/cvss/cvss-v3.0.xsd"\n' +
    '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n' +
    '  xsi:schemaLocation="https://www.first.org/cvss/cvss-v3.0.xsd https://www.first.org/cvss/cvss-v3.0.xsd"\n' +
    '  >\n' +
    '\n' +
    '  <base_metrics>\n' +
    '    <attack-vector>__AttackVector__</attack-vector>\n' +
    '    <attack-complexity>__AttackComplexity__</attack-complexity>\n' +
    '    <privileges-required>__PrivilegesRequired__</privileges-required>\n' +
    '    <user-interaction>__UserInteraction__</user-interaction>\n' +
    '    <scope>__Scope__</scope>\n' +
    '    <confidentiality-impact>__Confidentiality__</confidentiality-impact>\n' +
    '    <integrity-impact>__Integrity__</integrity-impact>\n' +
    '    <availability-impact>__Availability__</availability-impact>\n' +
    '    <base-score>__BaseScore__</base-score>\n' +
    '    <base-severity>__BaseSeverityRating__</base-severity>\n' +
    '  </base_metrics>\n' +
    '\n' +
    '  <temporal_metrics>\n' +
    '    <exploit-code-maturity>__ExploitCodeMaturity__</exploit-code-maturity>\n' +
    '    <remediation-level>__RemediationLevel__</remediation-level>\n' +
    '    <report-confidence>__ReportConfidence__</report-confidence>\n' +
    '    <temporal-score>__TemporalScore__</temporal-score>\n' +
    '    <temporal-severity>__TemporalSeverityRating__</temporal-severity>\n' +
    '  </temporal_metrics>\n' +
    '\n' +
    '  <environmental_metrics>\n' +
    '    <confidentiality-requirement>__ConfidentialityRequirement__</confidentiality-requirement>\n' +
    '    <integrity-requirement>__IntegrityRequirement__</integrity-requirement>\n' +
    '    <availability-requirement>__AvailabilityRequirement__</availability-requirement>\n' +
    '    <modified-attack-vector>__ModifiedAttackVector__</modified-attack-vector>\n' +
    '    <modified-attack-complexity>__ModifiedAttackComplexity__</modified-attack-complexity>\n' +
    '    <modified-privileges-required>__ModifiedPrivilegesRequired__</modified-privileges-required>\n' +
    '    <modified-user-interaction>__ModifiedUserInteraction__</modified-user-interaction>\n' +
    '    <modified-scope>__ModifiedScope__</modified-scope>\n' +
    '    <modified-confidentiality-impact>__ModifiedConfidentiality__</modified-confidentiality-impact>\n' +
    '    <modified-integrity-impact>__ModifiedIntegrity__</modified-integrity-impact>\n' +
    '    <modified-availability-impact>__ModifiedAvailability__</modified-availability-impact>\n' +
    '    <environmental-score>__EnvironmentalScore__</environmental-score>\n' +
    '    <environmental-severity>__EnvironmentalSeverityRating__</environmental-severity>\n' +
    '  </environmental_metrics>\n' +
    '\n' +
    '</cvssv3.0>\n';


  // Call CVSS.calculateCVSSFromMetrics to validate all the parameters and generate scores and severity ratings.
  // If that function returns an error, immediately return it to the caller of this function.
  var result = CVSS.calculateCVSSFromMetrics (
    AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Confidentiality, Integrity, Availability,
    ExploitCodeMaturity, RemediationLevel, ReportConfidence,
    ConfidentialityRequirement, IntegrityRequirement, AvailabilityRequirement,
    ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope,
    ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability);

  if (result.success !== true) {
    return result;
  }

  var xmlOutput = xmlTemplate;
  xmlOutput = xmlOutput.replace ("__AttackVector__",        CVSS.XML_MetricNames["MAV"][AttackVector]);
  xmlOutput = xmlOutput.replace ("__AttackComplexity__",    CVSS.XML_MetricNames["MAC"][AttackComplexity]);
  xmlOutput = xmlOutput.replace ("__PrivilegesRequired__",  CVSS.XML_MetricNames["MPR"][PrivilegesRequired]);
  xmlOutput = xmlOutput.replace ("__UserInteraction__",     CVSS.XML_MetricNames["MUI"][UserInteraction]);
  xmlOutput = xmlOutput.replace ("__Scope__",               CVSS.XML_MetricNames["MS"][Scope]);
  xmlOutput = xmlOutput.replace ("__Confidentiality__",     CVSS.XML_MetricNames["MCIA"][Confidentiality]);
  xmlOutput = xmlOutput.replace ("__Integrity__",           CVSS.XML_MetricNames["MCIA"][Integrity]);
  xmlOutput = xmlOutput.replace ("__Availability__",        CVSS.XML_MetricNames["MCIA"][Availability]);
  xmlOutput = xmlOutput.replace ("__BaseScore__",           result.baseMetricScore);
  xmlOutput = xmlOutput.replace ("__BaseSeverityRating__",  result.baseSeverity);

  xmlOutput = xmlOutput.replace ("__ExploitCodeMaturity__",     CVSS.XML_MetricNames["E"][ExploitCodeMaturity || "X"]);
  xmlOutput = xmlOutput.replace ("__RemediationLevel__",        CVSS.XML_MetricNames["RL"][RemediationLevel || "X"]);
  xmlOutput = xmlOutput.replace ("__ReportConfidence__",        CVSS.XML_MetricNames["RC"][ReportConfidence || "X"]);
  xmlOutput = xmlOutput.replace ("__TemporalScore__",           result.temporalMetricScore);
  xmlOutput = xmlOutput.replace ("__TemporalSeverityRating__",  result.temporalSeverity);

  xmlOutput = xmlOutput.replace ("__ConfidentialityRequirement__",  CVSS.XML_MetricNames["CIAR"][ConfidentialityRequirement || "X"]);
  xmlOutput = xmlOutput.replace ("__IntegrityRequirement__",        CVSS.XML_MetricNames["CIAR"][IntegrityRequirement || "X"]);
  xmlOutput = xmlOutput.replace ("__AvailabilityRequirement__",     CVSS.XML_MetricNames["CIAR"][AvailabilityRequirement || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedAttackVector__",        CVSS.XML_MetricNames["MAV"][ModifiedAttackVector || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedAttackComplexity__",    CVSS.XML_MetricNames["MAC"][ModifiedAttackComplexity || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedPrivilegesRequired__",  CVSS.XML_MetricNames["MPR"][ModifiedPrivilegesRequired || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedUserInteraction__",     CVSS.XML_MetricNames["MUI"][ModifiedUserInteraction || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedScope__",               CVSS.XML_MetricNames["MS"][ModifiedScope || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedConfidentiality__",     CVSS.XML_MetricNames["MCIA"][ModifiedConfidentiality || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedIntegrity__",           CVSS.XML_MetricNames["MCIA"][ModifiedIntegrity || "X"]);
  xmlOutput = xmlOutput.replace ("__ModifiedAvailability__",        CVSS.XML_MetricNames["MCIA"][ModifiedAvailability || "X"]);
  xmlOutput = xmlOutput.replace ("__EnvironmentalScore__",          result.environmentalMetricScore);
  xmlOutput = xmlOutput.replace ("__EnvironmentalSeverityRating__", result.environmentalSeverity);

  return { success: true, xmlString: xmlOutput };
};



/* ** CVSS.generateXMLFromVector **
 *
 * Takes Base, Temporal and Environmental metric values as a single string in the Vector String format defined
 * in the CVSS v3.0 standard definition of the Vector String.
 *
 * Returns an XML string representation of this input. See the comment for CVSS.generateXMLFromMetrics for more
 * detail on inputs, return values and errors. In addition to the error conditions listed for that function, this
 * function can also return:
 *   "MalformedVectorString", if the Vector String passed is does not conform to the format in the standard; or
 *   "MultipleDefinitionsOfMetric", if the Vector String is well formed but defines the same metric (or metrics),
 *                                  more than once.

CVSS.generateXMLFromVector = function ( vectorString ) {

  var metricValues = {
    AV:  undefined, AC:  undefined, PR:  undefined, UI:  undefined, S:  undefined,
    C:   undefined, I:   undefined, A:   undefined,
    E:   undefined, RL:  undefined, RC:  undefined,
    CR:  undefined, IR:  undefined, AR:  undefined,
    MAV: undefined, MAC: undefined, MPR: undefined, MUI: undefined, MS: undefined,
    MC:  undefined, MI:  undefined, MA:  undefined
  };

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];

  if (!CVSS.vectorStringRegex_30.test(vectorString)) {
    return { success: false, errorType: "MalformedVectorString" };
  }

  var metricNameValue = vectorString.substring(CVSS.CVSSVersionIdentifier.length).split("/");

  for (var i in metricNameValue) {
    if (metricNameValue.hasOwnProperty(i)) {

      var singleMetric = metricNameValue[i].split(":");

      if (typeof metricValues[singleMetric[0]] === "undefined") {
        metricValues[singleMetric[0]] = singleMetric[1];
      } else {
        badMetrics.push(singleMetric[0]);
      }
    }
  }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MultipleDefinitionsOfMetric", errorMetrics: badMetrics };
  }

  return CVSS.generateXMLFromMetrics (
    metricValues.AV,  metricValues.AC,  metricValues.PR,  metricValues.UI,  metricValues.S,
    metricValues.C,   metricValues.I,   metricValues.A,
    metricValues.E,   metricValues.RL,  metricValues.RC,
    metricValues.CR,  metricValues.IR,  metricValues.AR,
    metricValues.MAV, metricValues.MAC, metricValues.MPR, metricValues.MUI, metricValues.MS,
    metricValues.MC,  metricValues.MI,  metricValues.MA);
};
*/