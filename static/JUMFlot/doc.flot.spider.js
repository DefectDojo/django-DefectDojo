/*
 * The MIT License

Copyright (c) 2010, 2011, 2012, 2013 by Juergen Marsch

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

$.plot.JUMExample.docu.spider = {
"docu":"","spider":{
"docu":"<strong>Plugin to create spider chart</strong>","data":{
"docu":"Data Array specific for Spider chart","0":{
"docu":"first data entry","0":{
"docu":"number of spider leg, see options.spider.legs for some more info"}
,"1":{
"docu":"Value in spider leg"}
}
}
,"options":{
"docu":"options for Spider","series":{
"docu":"series options for Spider","spider":{
"docu":"Spider only options","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"show specific serie. this needs to be overwritten in data","defVal":"false"}
,"spiderSize":{
"docu":"Size of the full spider based on size of placeholder","defVal":"0.8"}
,"lineWidth":{
"docu":"Linewidth for grid lines","defVal":"3"}
,"lineStyle":{
"docu":"Drawing style for the Gridlines","defVal":"rgba(0,0,0,0.5)"}
,"pointSize":{
"docu":"Size of the marker on spiderleg. Its later used for highlighting a set of data","defVal":"6"}
,"scaleMode":{
"docu":"describes how min and max should be calculated. Options are leg to calculate each leg seperately or others to calculate one general value for all legs","defVal":"leg"}
,"legMin":{
"docu":"Overwrites calculated min scale for all legs. Smaller datapoints will be set to this value in display."}
,"legMax":{
"docu":"Overwrites calculated max scale for all legs. Greater datapoints will be set to this value in display"}
,"connection":{
"docu":"Option to describe the way to show connections between legs","width":{
"docu":"Linewidth to connect markers of a dataserie (BTW, can be 0 please test to see what happens)","defVal":"4"}
}
,"highlight":{
"docu":"Used for highlighting a serie","opacity":{
"docu":"Opacity (what else)","defVal":"0.5"}
,"mode":{
"docu":"Options are point (highlights markers on spider legs only, line (highlights lines from marker to marker, area (highlights the serie as a polygon, I love this one)","defVal":"point"}
}
,"legs":{
"docu":"Describes how the name for each leg is drawn","font":{
"docu":"","defVal":"20px Times New Roman"}
,"fillStyle":{
"docu":"","defVal":"Black"}
,"legScaleMin":{
"docu":"","defVal":"0.95"}
,"legScaleMax":{
"docu":"","defVal":"1.05"}
,"legStartAngle":{
"docu":"","defVal":"0"}
,"data":{
"docu":"","0":{
"docu":"","label":{
"docu":""}
}
,"1":{
"docu":"","label":{
"docu":""}
}
,"2":{
"docu":"","label":{
"docu":""}
}
,"3":{
"docu":"","label":{
"docu":""}
}
,"4":{
"docu":"","label":{
"docu":""}
}
}
}
}
,"editMode":{
"docu":""}
,"nearBy":{
"docu":"","distance":{
"docu":"","defVal":"6"}
,"findItem":{
"docu":""}
,"findMode":{
"docu":"","defVal":"circle"}
,"drawEdit":{
"docu":""}
,"drawHover":{
"docu":""}
}
}
}
,"defVal":"none"}
,"defVal":""}