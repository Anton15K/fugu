import os
os.environ['FUGU_NO_DOTENV']='1'
from .cli import main
raise SystemExit(main())
