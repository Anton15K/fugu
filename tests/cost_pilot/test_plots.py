import json,sys
import pytest
from bench.cost_pilot.plots import plot_results,chart_data,make_figures
from bench.cost_pilot.contracts import SafetyStop


def data():return {'schema_version':1,'planned_cases':2,'cases':[{'case':'c0','arm':'fugu','lane':'security','workflow':'partial','cost_lower_usd':.02,'cost_upper_usd':.08,'validated_tp':0},{'case':'c0','arm':'agent','lane':'security','workflow':'complete','cost_lower_usd':.03,'cost_upper_usd':.03,'validated_tp':1},{'case':'c1','arm':'fugu','lane':'functional','workflow':'unattempted','cost_lower_usd':None,'cost_upper_usd':None,'validated_tp':None},{'case':'c1','arm':'agent','lane':'functional','workflow':'unattempted','cost_lower_usd':None,'cost_upper_usd':None,'validated_tp':None}]}


def test_data_bounds_unattempted_and_lazy_import():
    c=chart_data(data());assert c['unattempted_rows']==2 and c['uncertain_rows']==1
    assert c['rows'][0]['cost_upper_usd']==.08
    assert all(r['cost_lower_usd'] is None for r in c['rows'] if r['workflow']=='unattempted')


@pytest.mark.parametrize('damage',['missing','reverse','unattempted_cost'])
def test_invalid_data_refused(damage):
    d=data()
    if damage=='missing':d['cases'].pop()
    elif damage=='reverse':d['cases'][0]['cost_upper_usd']=.01
    else:d['cases'][2]['cost_lower_usd']=.05
    with pytest.raises(SafetyStop):chart_data(d)


def test_charts_show_unknown_and_decode_png_pdf(tmp_path,monkeypatch):
    pytest.importorskip('matplotlib')
    import socket
    monkeypatch.setattr(socket.socket,'connect',lambda *a,**kw:(_ for _ in ()).throw(AssertionError('network')))
    from PIL import Image
    path=tmp_path/'results.json';path.write_text(json.dumps(data()))
    files=plot_results(path,tmp_path/'charts')
    assert {p.name for p in files}=={'cost-correctness.png','cost-correctness.pdf','per-case-cost.png','per-case-cost.pdf','chart-data.json'}
    chart=json.loads((tmp_path/'charts/chart-data.json').read_text())
    assert chart['unattempted_rows']==2 and chart['uncertain_rows']==1
    for p in files:
        assert p.stat().st_size>100
        if p.suffix=='.png':
            with Image.open(p) as img:img.load();assert img.size[0]>500 and img.size[1]>300
        elif p.suffix=='.pdf':assert p.read_bytes().startswith(b'%PDF-') and b'/Type /Page' in p.read_bytes()
    assert 'openai' not in sys.modules and 'keyring' not in sys.modules


def test_actual_figure_axes_artists_and_caption():
    pytest.importorskip('matplotlib')
    from matplotlib import pyplot as plt
    figures=make_figures(chart_data(data()))
    try:
        assert len(figures)==2
        axes=figures[0].axes
        assert any('Estimated' in a.get_xlabel() for a in axes)
        assert any('Validated' in a.get_ylabel() for a in axes)
        assert any('not measured' in t.get_text() for fig in figures for a in fig.axes for t in a.texts)
        assert any('OSV' in t.get_text() for fig in figures for t in fig.texts)
        assert any(a.containers for fig in figures for a in fig.axes)
    finally:
        for f in figures:plt.close(f)


def test_status_caption_does_not_cover_data():
    pytest.importorskip('matplotlib')
    from matplotlib import pyplot as plt
    figures=make_figures(chart_data(data()))
    try:
        for fig in figures:
            for ax in fig.axes:
                status=next(t for t in ax.texts if 'complete;' in t.get_text())
                assert status.get_position()[1]>1
    finally:
        for fig in figures:plt.close(fig)
