export interface TestIP {
  country: string;
  city: string;
  ip: string;
  note?: string;
}

export const TEST_IPS: TestIP[] = [
  {
    country: "🇺🇸 USA",
    city: "New York",
    ip: "162.249.172.18",
    note: "Google DNS",
  },
  {
    country: "🇬🇧 UK",
    city: "London",
    ip: "212.58.244.22",
    note: "BBC",
  },
  {
    country: "🇨🇦 Canada",
    city: "Toronto",
    ip: "99.79.60.118",
    note: "AWS Canada Central",
  },
  {
    country: "🇩🇪 Germany",
    city: "Frankfurt",
    ip: "18.196.0.1",
    note: "AWS Frankfurt",
  },
  {
    country: "🇧🇷 Brazil",
    city: "São Paulo",
    ip: "177.99.243.2",
  },
  {
    country: "🇯🇵 Japan",
    city: "Tokyo",
    ip: "210.140.92.1",
  },
  {
    country: "🇮🇳 India",
    city: "Mumbai",
    ip: "15.206.0.1",
    note: "AWS Mumbai",
  },
  {
    country: "🇦🇺 Australia",
    city: "Sydney",
    ip: "13.54.0.1",
    note: "AWS Sydney",
  },
  {
    country: "🇿🇦 South Africa",
    city: "Johannesburg",
    ip: "102.133.0.1",
    note: "MTN",
  },
  {
    country: "🇳🇬 Nigeria",
    city: "Lagos",
    ip: "41.58.1.1",
    note: "MTN Nigeria",
  },
];
