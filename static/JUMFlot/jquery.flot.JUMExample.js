/*
 * The MIT License

Copyright (c) 2012, 2013 by Juergen Marsch

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
(function ($) {
    "use strict";
	function init(pluginname,dt,op){
		var r = "";
		var i;
		for(i = 0; i < dt.length; i++){
			r += "<h3>" + dt[i].header + "</h3>";
			r += objectStringifyHTML(dt[i].data);
		}
		$("#placeholderData").html(r);
		r = "";
		for(i = 0; i < op.length; i++){
			r += "<h3>" + op[i].header + "</h3>";
			r += objectToDocumentation(op[i].data,pluginname + "." + pluginname + ".options");
		}
		$("#placeholderOption").html(r);
		if(debugOn === false) { $(".flot_debug").hide(); } 
		$("#tabs").tabs();
		try{showSource("../../Experimental/jquery.Flot." + pluginname + ".js");}
		catch(e){console.log(e);}
		$("#placeholderManual").html(docuObjectToHTML($.plot.JUMExample.docu[pluginname]));
		$(".jumflothelp").on("mouseover",showDocuHelp);
		$(".jumflothelp").on("mouseleave",function(){$("#FLOTtooltip").remove();});
	}
    function showDocuHelp(pos){
		var attr = $(this)[0].attributes;
		var txt = getAPIHelp(attr["docuobj"].nodeValue,attr["prevname"].nodeValue,attr["actname"].nodeValue);
		$.plot.JUMlib.library.showTooltip(pos.pageX,pos.pageY,txt);
	}
	var actDocu = {data:null,form:null,target:null};
	function getDocu(p,pluginname,t){
	    var opt = p.getOptions();
	    var d = opt.series[pluginname] || opt.grid[pluginname] || opt[pluginname];
		var r = d.debug.createDocuTemplate();
		actDocu.data = r.data; actDocu.form = r.form; actDocu.target = t;
		$(actDocu.target).html(actDocu.form);
	}
	function setDocu(f,v){ 
		var c = "actDocu.data",flds;
		flds = f.split('.');
		c = "actDocu.data";
		v = v.replace(/\r\n|\r|\n/g,"<br>");
		for(var i = 0; i < flds.length; i++){ if(flds[i].length > 0){ c += "[\"" + flds[i] + "\"]" ; } }
		c += "='" + v + "'";
		eval(c); 
	}
	function createJSON(){
		var r = JSON.stringify(actDocu.data);
		r = r.replace(/{/g,"{\n"); r = r.replace(/}/g,"}\n");
		$(actDocu.target).html('<textarea rows="12" cols="80">' + r + "</textarea>"); 
	}
	function showSource(url){
		function gotSource(src){ $("#placeholderSource").html(src);}
        $.ajax({ url: url, method: 'GET',dataType: 'text',success: gotSource,error:function(e,x,y){console.log(e,x,y);} }); 
	}

    function docuObjectToTemplate(areas,name){
        var objStart,objEnd,obj,msg,takedef,j,z;
        objStart = 'z = {"docu":""\n';
        objStart += ',' + name + ':{"docu":""\n';
        objEnd = '\n}\n}';
        obj = eval(objStart + objEnd);
        for(var i = 0; i < areas.length; i++){
            msg = objStart;
            var names = areas[i].name.split('.');
            msg += ',';
            for(j = 0; j < names.length - 1; j++){
                msg += names[j] + ':{"docu":"",';
            }
            msg += names[names.length - 1] + ':';
            if(areas[i].takeDefault){ takedef = areas[i].takeDefault;} else{ takedef = false; }
            msg += docuSubtree(areas[i].tree,takedef) + '}';
            for(j = 0; j < names.length -1; j++){
                msg += '}';
            }
            msg += objEnd;
            $.extend(true,obj,eval(msg));
        }
        return obj;
        function docuSubtree(obj,takedef){
            var msg = "";

            if(typeof obj === "object"){
                msg = '{"docu":""';
                for(var i in obj){
                    if(typeof obj[i] === "object"){ 
                        if(i !== "image"){
                            if($.isNumeric(i)){ msg += '\n,"' + i + '":'; }
                            else{msg += '\n,' + i + ':'; }
                            msg += docuSubtree(obj[i],takedef);
                            msg +='}';
                        }
                        else{ msg+= "\n," + i + ':{"docu":""}'; }
                    }
                    else if(typeof obj[i] === "function"){ 
                        var fn = obj[i].toSource();
                        fn = fn.substr(8,fn.indexOf(')') - 7 );
                        if(takedef === true) { msg += '\n,"' + i + '":{"docu":""}'; }
                        else {msg += '\n,"' + i + '":{"docu":"",defVal:"' + fn + '"}'; }
                    }
                    else { 
                        if(takedef === true) {msg += '\n,"' + i + '":{"docu":"","defVal":"' + obj[i] + '"}'; }
                        else {msg += '\n,"' + i + '":{"docu":""}'; }
                    }
                }
            }
            else {msg += '{"docu":""'; }
            return msg;
        }
    }
    function extendDocuObject(n,p){
        var o = $.plot.JUMExample.docu[p];
        var d = n[p].data;
        for(var i in d){ if(i !== "0" && i !== "docu" && i !== "defVal") {delete d[i];} }
        if(o){ extendTree(n,o); }
        $.extend(true,n,o);
        function extendTree(n,o){
            for(var i in n){
                if(typeof n[i] === "object"){if(o[i]) { extendTree(n[i],o[i]); } }
                else if(i === "docu"){ if(o.docu) {if(o.docu.length > 0) {n.docu = o.docu; } } }
                else if(i === "defVal"){ if(o.defVal) {if(o.defVal.length > 0) {n.defVal = o.defVal; } } }
            }
        }
    }
    function docuObjectToEdit(obj,name){
        var msg = '<form name="editObject">';
        msg += '<input type="button" value="Create json" onclick="$.plot.JUMExample.createJSON();">';
        msg += extendTree(obj,name);
        function extendTree(obj,prev){
            msg = '<ul>';
            msg += '<li>' + prev.substr(prev.lastIndexOf('.') + 1);
            if(obj.defVal){msg += ' <i>default:' + obj.defVal + '</i>';}
            msg += '<br>';
            msg += getInput(obj.docu,prev) + '<br>';
            for(var i in obj){
                if(typeof obj[i] === "object"){
                    msg += extendTree(obj[i],prev + '.' + i);
                }
            }
            msg += '</ul>';
            return msg;
        }
        function getInput(txt,prev){
            var s;
            s = "$.plot.JUMExample.setDocu('" + prev + ".docu" + "',this.value);";
            return '<textarea cols="50" rows="3" onblur="' + s + '" >' + txt + '</textarea>';
        }
        msg += '</form>';
        return msg;
    }
    function docuObjectToHTML(obj,maxdepth,depth){
        if(!maxdepth){ maxdepth = 8; }
        var msg = "";
        if(!depth){ depth = 0; msg += '<ul id="sitemap" class="treeview">\n';}
        else{ msg += '<ul>\n'; }
        if(typeof obj === "object") {
            for(var i in obj){
                if(typeof obj[i] === "object"){
                    if($.isNumeric(i)){ msg += '<b>[' + i + ']</b>';} else {msg += '<li><b>' + i + '</b>'; }
                    if(obj[i].docu) { msg += '&nbsp;<dfn>' + obj[i].docu + '</dfn>'; }
                    if(obj[i].defVal) { if(obj[i].defVal !== "none") {msg += '&nbsp;(<code>' + obj[i].defVal + '</code>)'; } }
                    msg += '</li>\n';
                    if(maxdepth > depth) {msg += docuObjectToHTML(obj[i],maxdepth,depth + 1); }
                }
                else { if(i !== 'docu' && i !== 'defVal'){ msg += '<li>' + obj[i] + '</li>\n'; } }
            }
        }
        msg += '</ul>\n';
        return msg;
    }
    function objectToDocumentation(obj,docuObjName,maxdepth,showfunction,depth,prevname){
        if(!maxdepth){ maxdepth = 6; }
        if(!showfunction){ showfunction = false; }
        return docuSubtree(obj,-1,"");
        function docuSubtree(obj,depth,prevname){
            var msg = "";
            if(depth<0){ depth = 0; msg += '<ul id="sitemap" class="treeview">\n';}
            else { msg +='<ul>\n'; }
            if(typeof obj === "object") {
                for(var i in obj){
                    if (typeof obj[i] === "object"){
                        msg += '<li><b>' + getHelpUrl(prevname,i) + '</b>&nbsp;<i>' + getTypeOf(obj[i]) + '</i></li>\n';
                        if(maxdepth > depth) { msg += docuSubtree(obj[i],depth + 1, prevname + '.' + i); }
                    }
                    else if(typeof obj[i] === "function"){
                        if(showfunction === true) { msg += '<li>' + getHelpUrl(prevname,i) + '&nbsp;' + obj[i].toString() + "</li>\n"; }
                        else { msg += '<li>' + getHelpUrl(prevname,i) + '&nbsp;<i>' + getTypeOf(obj[i]) + '</i></li>\n'; }
                    }
                    else { msg += '<li>' + getHelpUrl(prevname,i) + '=' + getString(obj[i]) + '&nbsp;<i>' + getTypeOf(obj[i]) + '</i></li>\n'; }
                }
            }
            else{ msg += '<li>' + obj + '&nbsp;<i>' + getTypeOf(obj) + '</i></li>\n'; }
            msg += '</ul>\n';
            return msg;
        }
        function getHelpUrl(prevname,actname){
            return '<span class="jumflothelp" docuobj="' + docuObjName + '" prevname="' + prevname + '" actname="' + actname + '">' + actname + '</span>';
        }
        function getString(x){
            var y = x;
            if (typeof y === "string") {
                y = y.replace(/</g, "&lt;");
                y = y.replace(/>/g, "&gt;");
            }
            return y;
        }
        function getTypeOf(x){
            var r;
            r = typeof x;
            if($.isArray(x)){ r += " Array"; }
            return r;
        }
    }
    function objectStringifyHTML(obj){
        var r = JSON.stringify(obj);
        r = r.replace(/{/g,"{<blockquote style=\"padding:1px; margin-top:1px; margin-bottom:1px\">");
        r = r.replace(/}/g,"</blockquote>}");
        r = r.replace(/\[/g,"[<blockquote style=\"padding:1px; margin-top:1px; margin-bottom:1px\">");
        r = r.replace(/\]/g,"</blockquote>]");
        return r;
    }
    function getAPIHelp(docuObjName,prevName,actName){
        var val = "",nm = "$.plot.JUMExample.docu." + docuObjName + prevName + "." + actName;
        try {
            if(eval(nm + ".docu")){ val = eval(nm + ".docu"); }
            if(eval(nm + ".Default")){ val += "Default:" + eval(nm + ".Default"); }
        }
        catch(err){
            val += "nothing found, please see flot API";
        }
        return(nm + "<hr>" + val);
    }
  
    $.plot.JUMExample = {};
    $.plot.JUMExample.init = init;
    $.plot.JUMExample.showDocuHelp = showDocuHelp;
    $.plot.JUMExample.getDocu = getDocu;
    $.plot.JUMExample.setDocu = setDocu;
    $.plot.JUMExample.createJSON = createJSON;
    $.plot.JUMExample.showSource = showSource;
    $.plot.JUMExample.docuObjectToTemplate = docuObjectToTemplate;
    $.plot.JUMExample.extendDocuObject = extendDocuObject;
    $.plot.JUMExample.docuObjectToEdit = docuObjectToEdit;
    $.plot.JUMExample.docuObjectToHTML = docuObjectToHTML;
    $.plot.JUMExample.objectToDocumentation = objectToDocumentation;
    $.plot.JUMExample.objectStringifyHTML = objectStringifyHTML;
    $.plot.JUMExample.getAPIHelp = getAPIHelp;
    $.plot.JUMExample.docu = {};
})(jQuery);

