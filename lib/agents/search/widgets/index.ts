import weatherWidget from './weatherWidget';
import calculationWidget from './calculationWidget';
import WidgetExecutor from './executor';

WidgetExecutor.register(weatherWidget);
WidgetExecutor.register(calculationWidget);
// stockWidget disabled due to yahoo-finance2 dependency issues

export { WidgetExecutor };
