import ChatWindow from '@/components/ChatWindow';
import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Chat - Windrose',
  description: 'Chat with the internet, chat with Windrose.',
};

const Home = () => {
  return <ChatWindow />;
};

export default Home;
