// Weather lookup skill
const API_BASE = 'https://api.openweathermap.org/data/2.5';

export async function getWeather(location) {
  const response = await fetch(`${API_BASE}/weather?q=${encodeURIComponent(location)}&appid=${process.env.OPENWEATHER_KEY}`);
  const data = await response.json();
  return {
    temp: data.main.temp,
    description: data.weather[0].description,
    humidity: data.main.humidity,
  };
}

export async function getForecast(location) {
  const response = await fetch(`${API_BASE}/forecast?q=${encodeURIComponent(location)}&appid=${process.env.OPENWEATHER_KEY}`);
  const data = await response.json();
  return data.list.map(item => ({
    date: item.dt_txt,
    temp: item.main.temp,
    description: item.weather[0].description,
  }));
}
