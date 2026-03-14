from core.discovery.param_discovery import ParameterDiscoveryEngine

def test_param_discovery():

    engine = ParameterDiscoveryEngine()

    injections = engine.discover("http://example.com")

    assert isinstance(injections, list)