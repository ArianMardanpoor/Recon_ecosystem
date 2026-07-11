// client/src/App.tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'; //[cite: 4]
import { Toaster } from "@/components/ui/sonner"; //[cite: 4]
import { TooltipProvider } from "@/components/ui/tooltip"; //[cite: 4]
import { Route, Switch } from "wouter"; //[cite: 4]
import ErrorBoundary from "./components/ErrorBoundary"; //[cite: 4]
import { ThemeProvider } from "./contexts/ThemeContext"; //[cite: 4]

import Dashboard from "./pages/Dashboard"; //[cite: 4]
import Programs from "./pages/Programs"; //[cite: 4]
import Subdomains from "./pages/Subdomains"; //[cite: 4]
import LiveSubdomains from "./pages/LiveSubdomains"; //[cite: 4]
import HttpServices from "./pages/HttpServices"; //[cite: 4]
import Assets from "./pages/Assets"; //[cite: 4]
import NotFound from "./pages/NotFound"; //[cite: 4]

// صفحه جدید را ایمپورت می‌کنیم
import HttpServiceDetail from "./pages/HttpServiceDetail"; 

const queryClient = new QueryClient(); //[cite: 4]

function Router() { //[cite: 4]
  return ( //[cite: 4]
    <Switch> 
      <Route path="/" component={Dashboard} /> 
      <Route path="/programs" component={Programs} /> 
      <Route path="/subdomains" component={Subdomains} /> 
      <Route path="/live-subdomains" component={LiveSubdomains} /> 
      <Route path="/http-services" component={HttpServices} /> 
      {/* مسیر جدید اضافه شده */}
      <Route path="/http-services/:subdomain" component={HttpServiceDetail} />
      
      <Route path="/assets" component={Assets} /> 
      <Route path="/404" component={NotFound} /> 
      <Route component={NotFound} /> 
    </Switch> //[cite: 4]
  ); //[cite: 4]
} //[cite: 4]

function App() { //[cite: 4]
  return ( //[cite: 4]
    <ErrorBoundary> 
      <QueryClientProvider client={queryClient}> 
        <ThemeProvider defaultTheme="dark"> 
          <TooltipProvider> 
            <Toaster /> 
            <Router /> 
          </TooltipProvider> 
        </ThemeProvider> 
      </QueryClientProvider> 
    </ErrorBoundary> //[cite: 4]
  ); //[cite: 4]
} //[cite: 4]

export default App; //[cite: 4]