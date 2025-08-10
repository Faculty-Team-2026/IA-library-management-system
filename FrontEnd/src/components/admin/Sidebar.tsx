import { IconDefinition } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

interface SidebarItem {
  key: string;
  icon: IconDefinition;
  label: string;
}

interface SidebarProps {
  items: SidebarItem[];
  activeKey: string;
  onSelect: (key: string) => void;
  isMobileOpen?: boolean;
  onMobileClose?: () => void;
}

const Sidebar = ({ 
  items, 
  activeKey, 
  onSelect,
  isMobileOpen = false,
  onMobileClose = () => {}
}: SidebarProps) => {
  return (
    <>
      {/* Mobile overlay */}
      {isMobileOpen && (
        <div 
          className="md:hidden fixed inset-0 bg-black bg-opacity-50 z-20"
          onClick={onMobileClose}
        />
      )}
      
      {/* Sidebar */}
      <aside 
        className={`
          fixed md:static top-20 md:top-0 bottom-0 left-0 z-30
          w-64 bg-white border-r border-violet-400 flex flex-col py-8 px-4
          transition-transform duration-300 ease-in-out
          ${isMobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
        `}
      >
        {/* Mobile close button */}
        <button 
          className="md:hidden absolute top-4 right-4 text-gray-500 hover:text-gray-700"
          onClick={onMobileClose}
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
        
        <div className="mt-6 md:mt-0">
          {items.map((item) => (
            <button
              key={item.key}
              onClick={() => {
                onSelect(item.key);
                if (window.innerWidth < 768) {
                  onMobileClose();
                }
              }}
              className={`flex items-center gap-3 px-4 py-3 mb-2 rounded-lg cursor-pointer text-left w-full bg-white ${
                activeKey === item.key
                  ? "text-green-700 font-semibold border-l-4 border-green-500 bg-green-50"
                  : "text-gray-500 hover:bg-green-50 hover:text-green-600 transition-colors duration-200"
              }`}
            >
              <FontAwesomeIcon icon={item.icon} className="text-xl" />
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
