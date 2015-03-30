$(function () {
    $(".datepicker").datepicker();

    $.tablesorter.addParser({
        id: 'severity',
        is: function (s) {
            return false;
        },
        format: function (s) {
            return s.toLowerCase().replace(/critical/, 0).replace(/high/, 1).replace(/medium/, 2).replace(/low/, 3).replace(/info/, 4);
        },
        type: 'numeric'
    });

    $('#tabs').tabs();

    $('form#replace_risk_file input[type="file"], div.controls.file input').change(function () {
        $(this).closest("form").submit()
    });

    $('a.accept-all-findings').click(function () {
        $("ul#id_accepted_findings input").attr('checked', true);
    })

});

$(function () {

    $('#side-menu').metisMenu(
        {doubleTapToGo: true}
    );

});

